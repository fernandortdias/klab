package org.integratedmodelling.klab.ide.utils;

import java.awt.Toolkit;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.net.MalformedURLException;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.logging.Level;

import org.eclipse.core.filesystem.EFS;
import org.eclipse.core.filesystem.IFileStore;
import org.eclipse.core.resources.IFile;
import org.eclipse.core.resources.IMarker;
import org.eclipse.core.resources.IProject;
import org.eclipse.core.resources.IProjectDescription;
import org.eclipse.core.resources.IResource;
import org.eclipse.core.resources.IWorkspaceRoot;
import org.eclipse.core.resources.ResourcesPlugin;
import org.eclipse.core.resources.WorkspaceJob;
import org.eclipse.core.runtime.CoreException;
import org.eclipse.core.runtime.IProgressMonitor;
import org.eclipse.core.runtime.IStatus;
import org.eclipse.core.runtime.NullProgressMonitor;
import org.eclipse.core.runtime.Path;
import org.eclipse.core.runtime.Status;
import org.eclipse.core.runtime.URIUtil;
import org.eclipse.jface.dialogs.MessageDialog;
import org.eclipse.jface.viewers.ITreeContentProvider;
import org.eclipse.jface.viewers.LabelProvider;
import org.eclipse.jface.window.Window;
import org.eclipse.swt.graphics.Image;
import org.eclipse.swt.widgets.Display;
import org.eclipse.swt.widgets.Shell;
import org.eclipse.ui.IEditorReference;
import org.eclipse.ui.IViewPart;
import org.eclipse.ui.IWorkbenchPage;
import org.eclipse.ui.IWorkbenchWindow;
import org.eclipse.ui.PartInitException;
import org.eclipse.ui.PlatformUI;
import org.eclipse.ui.console.ConsolePlugin;
import org.eclipse.ui.console.IConsole;
import org.eclipse.ui.console.IConsoleManager;
import org.eclipse.ui.console.MessageConsole;
import org.eclipse.ui.console.MessageConsoleStream;
import org.eclipse.ui.dialogs.CheckedTreeSelectionDialog;
import org.eclipse.ui.dialogs.IOverwriteQuery;
import org.eclipse.ui.ide.IDE;
import org.eclipse.ui.part.FileEditorInput;
import org.eclipse.ui.progress.UIJob;
import org.eclipse.ui.statushandlers.StatusManager;
import org.eclipse.ui.wizards.datatransfer.FileSystemStructureProvider;
import org.eclipse.ui.wizards.datatransfer.ImportOperation;
import org.eclipse.xtext.resource.XtextResource;
import org.eclipse.xtext.ui.editor.XtextEditor;
import org.eclipse.xtext.ui.editor.utils.EditorUtils;
import org.eclipse.xtext.util.concurrent.IUnitOfWork;
import org.integratedmodelling.kim.api.IKimNamespace;
import org.integratedmodelling.kim.api.IKimProject;
import org.integratedmodelling.klab.exceptions.KlabException;
import org.integratedmodelling.klab.exceptions.KlabIOException;
import org.integratedmodelling.klab.ide.Activator;
import org.integratedmodelling.klab.ide.navigator.model.EKimObject;
import org.integratedmodelling.klab.ide.navigator.model.ENamespace;
import org.integratedmodelling.klab.rest.CompileNotificationReference;
import org.integratedmodelling.klab.rest.NamespaceCompilationResult;

public enum Eclipse {

	INSTANCE;

	public static final String KLAB_CONSOLE_ID = "klab.console";

	private MessageConsole findConsole(String name) {
		ConsolePlugin plugin = ConsolePlugin.getDefault();
		IConsoleManager conMan = plugin.getConsoleManager();
		IConsole[] existing = conMan.getConsoles();
		for (int i = 0; i < existing.length; i++)
			if (name.equals(existing[i].getName()))
				return (MessageConsole) existing[i];
		// no console found, so create a new one
		MessageConsole myConsole = new MessageConsole(name, null);
		conMan.addConsoles(new IConsole[] { myConsole });
		return myConsole;
	}

	// Creating a console and writing to it do not create or reveal the Console
	// view. If you want to make that sure the Console view is visible, you need to
	// reveal it using the usual workbench API. Even once the Console view is
	// revealed, keep in mind that it may contain several pages, each representing a
	// different IConsole provided by a plug-in. Additional API asks the Console
	// view to display your console. This snippet reveals the Console view and asks
	// it to display a particular console instance:
	//
	// IConsole myConsole = ...;// your console instance
	// IWorkbenchPage page = ...;// obtain the active page
	// String id = IConsoleConstants.ID_CONSOLE_VIEW;
	// IConsoleView view = (IConsoleView) page.showView(id);
	// view.display(myConsole);
	public void writeToConsole(String string) {
		MessageConsole myConsole = findConsole(KLAB_CONSOLE_ID);
		MessageConsoleStream out = myConsole.newMessageStream();
		out.println(string);
	}

	/**
	 * Open the passed view. Optionally pass an action to call when the view has
	 * been shown.
	 * 
	 * @param id
	 *            ID of the view
	 * @param action
	 *            an action to perform on the view once open, or null
	 */
	public void openView(final String id, final Consumer<IViewPart> action) {

		class Job extends UIJob {
			public Job() {
				super("");
			}

			@Override
			public IStatus runInUIThread(IProgressMonitor monitor) {
				try {
					IViewPart view = PlatformUI.getWorkbench().getActiveWorkbenchWindow().getActivePage().showView(id);
					if (view != null && action != null) {
						action.accept(view);
					}
				} catch (PartInitException e) {
					handleException(e);
				}
				return Status.OK_STATUS;
			}
		}
		Job job = new Job();
		job.setUser(false);
		job.schedule();
		try {
			job.join();
		} catch (InterruptedException e) {
			handleException(e);
		}
	}

	/**
	 * Open string content in passed editor. Use a temp file and avoid all
	 * absurdities.
	 * 
	 * @param content
	 * @param editorId
	 * @param readOnly
	 */
	public void edit(String content, String filename, String extension, boolean readOnly) {

		File tempDir = new File(System.getProperty("java.io.tmpdir"));
		try {
			File tempFile = File.createTempFile(filename, "." + extension, tempDir);
			FileWriter fileWriter = new FileWriter(tempFile, false);
			BufferedWriter bw = new BufferedWriter(fileWriter);
			bw.write(content);
			bw.close();

			IFileStore fileStore = EFS.getLocalFileSystem().fromLocalFile(tempFile);
			if (fileStore.fetchInfo().exists()) {
				IWorkbenchPage page = PlatformUI.getWorkbench().getActiveWorkbenchWindow().getActivePage();
				try {
					IDE.openEditorOnFileStore(page, fileStore);
				} catch (PartInitException e) {
					handleException(e);
				}
			}
		} catch (Exception e) {
			handleException(e);
		}
	}

	public Shell getShell() {
		IWorkbenchWindow window = PlatformUI.getWorkbench().getActiveWorkbenchWindow();
		if (window == null) {
			IWorkbenchWindow[] windows = PlatformUI.getWorkbench().getWorkbenchWindows();
			if (windows.length > 0) {
				return windows[0].getShell();
			}
		} else {
			return window.getShell();
		}
		return null;
	}

	/**
	 * Open a file in the editor at the passed line number.
	 * 
	 * @param filename
	 * @param lineNumber
	 * @throws KlabException
	 */
	public void openFile(String filename, int lineNumber) throws KlabException {

		/*
		 * open as workspace file - otherwise xtext gives an exception
		 */
		IFile file = null;
		if (filename.startsWith("file:")) {
			URL url = null;
			try {
				url = new URL(filename);
			} catch (MalformedURLException e) {
				throw new KlabIOException(e);
			}
			filename = url.getFile().toString();
		}
		File dfile = new File(filename);
		if (dfile.exists()) {
			// full file path
			IFile[] ff = ResourcesPlugin.getWorkspace().getRoot().findFilesForLocationURI(dfile.toURI());
			if (ff != null && ff.length > 0) {
				file = ff[0];
			}
		} else {
			Path path = new Path(filename);
			file = ResourcesPlugin.getWorkspace().getRoot().getFile(path);
		}

		openFile(file, lineNumber);
	}

	public void openFile(IFile file, int lineNumber) {

		IWorkbenchPage page = PlatformUI.getWorkbench().getActiveWorkbenchWindow().getActivePage();
		try {
			if (lineNumber > 0) {
				HashMap<String, Object> map = new HashMap<>();
				map.put(IMarker.LINE_NUMBER, new Integer(lineNumber));
				IMarker marker = file.createMarker(IMarker.TEXT);
				marker.setAttributes(map);
				IDE.openEditor(page, marker);
				marker.delete();
			} else {
				IDE.openEditor(page, file);
			}
		} catch (Exception e) {
			error(e);
		}
	}

	public IFile getIFile(IKimNamespace namespace) {
		IWorkspaceRoot root = ResourcesPlugin.getWorkspace().getRoot();
		IProject project = root.getProject(namespace.getProject().getName());
		if (project == null) {
			if (namespace.getFile() != null) {
				return getIFile(namespace.getFile());
			}
			return null;
		}
		String rpath = null;
		if (namespace.isWorldviewBound()) {
			String kimPrefix = "/";
			if (namespace.getScriptId() != null) {
				kimPrefix = IKimProject.SCRIPT_FOLDER + "/";
			} else if (namespace.getTestCaseId() != null) {
				kimPrefix = IKimProject.TESTS_FOLDER + "/";
			} else {
				// oh fuck
			}
			rpath = kimPrefix + namespace.getResourceId().substring(namespace.getResourceId().lastIndexOf('/') + 1);
		} else {
			rpath = "src/" + namespace.getName().replace('.', '/') + ".kim";
		}
		return project.getFile(rpath);
	}

	public IFile getNamespaceIFile(EKimObject object) {
		ENamespace namespace = object.getEParent(ENamespace.class);
		if (namespace != null) {
			IWorkspaceRoot root = ResourcesPlugin.getWorkspace().getRoot();
			IProject project = root.getProject(namespace.getProject().getName());
			String rpath = null;
			if (namespace.isWorldviewBound()) {
				String kimPrefix = "/";
				if (namespace.getScriptId() != null) {
					kimPrefix = IKimProject.SCRIPT_FOLDER + "/";
				} else if (namespace.getTestCaseId() != null) {
					kimPrefix = IKimProject.TESTS_FOLDER + "/";
				} else {
					// oh fuck
				}
				rpath = kimPrefix + namespace.getResourceId().substring(namespace.getResourceId().lastIndexOf('/') + 1);
			} else {
				rpath = "src/" + namespace.getName().replace('.', '/') + ".kim";
			}
			return project.getFile(rpath);
		}
		return null;
	}

	public String getNamespaceIdFromIFile(IFile file) {

		if (file.toString().endsWith(".kim")) {
			if (file.getProject() == null) {
				return null;
			}
			String project = file.getProject().getName();
			String kimPrefix = "";
			if (file.toString().contains(IKimProject.SOURCE_FOLDER)) {
				kimPrefix = IKimProject.SOURCE_FOLDER;
			} else if (file.toString().contains(IKimProject.SCRIPT_FOLDER)) {
				kimPrefix = IKimProject.SCRIPT_FOLDER;
			} else if (file.toString().contains(IKimProject.TESTS_FOLDER)) {
				kimPrefix = IKimProject.TESTS_FOLDER;
			}
			kimPrefix = project + "/" + kimPrefix + "/";
			String ret = file.toString().substring(file.toString().indexOf(kimPrefix) + kimPrefix.length());
			return ret.substring(0, ret.length() - 4).replaceAll("\\/", ".");
		}
		return null;
	}

	private void error(Exception e) {
		// TODO Auto-generated method stub
		System.out.println("SHIT, HANDLE ME: " + e);
	}

	public void openFile(String filename) throws KlabException {
		openFile(filename, 0);
	}

	/**
	 * Import an Eclipse project programmatically into the workspace. Does not check
	 * for existence and overwrites whatever is there.
	 * 
	 * @param baseDir
	 * @return
	 */
	public IProject importExistingProject(File baseDir) {

		IProject project = null;

		try {
			IProjectDescription description = ResourcesPlugin.getWorkspace()
					.loadProjectDescription(new Path(baseDir.getPath() + "/.project"));
			project = ResourcesPlugin.getWorkspace().getRoot().getProject(description.getName());
			project.create(description, null);

			IOverwriteQuery overwriteQuery = new IOverwriteQuery() {

				public String queryOverwrite(String file) {
					return ALL;
				}
			};

			ImportOperation importOperation = new ImportOperation(project.getFullPath(), baseDir,
					FileSystemStructureProvider.INSTANCE, overwriteQuery);
			importOperation.setCreateContainerStructure(false);
			importOperation.run(new NullProgressMonitor());

			project.open(new NullProgressMonitor());

		} catch (Exception e) {
			error(e);
		}

		return project;
	}

	public void alert(String message) {
		try {
			IWorkbenchWindow window = PlatformUI.getWorkbench().getActiveWorkbenchWindow();
			Shell shell = window == null ? new Shell(new Display()) : window.getShell();
			MessageDialog.openError(shell, "Error", message);
		} catch (Throwable e) {
			// last resort
			System.out.println("ALERT: " + message);
		}
	}

	public boolean confirm(String message) {
		Shell shell = PlatformUI.getWorkbench().getActiveWorkbenchWindow().getShell();
		return MessageDialog.openQuestion(shell, "Confirmation", message);
	}

	public void warning(String message) {
		Shell shell = PlatformUI.getWorkbench().getActiveWorkbenchWindow().getShell();
		MessageDialog.openWarning(shell, "Warning", message);
	}

	public void info(String message) {
		Shell shell = PlatformUI.getWorkbench().getActiveWorkbenchWindow().getShell();
		MessageDialog.openInformation(shell, "Information", message);
	}

	public <T> T chooseOne(String question, Collection<T> alternatives) {
		return null;
	}

	public void closeEditor(File file, IWorkbenchPage page) {

		IFile resource = getIFile(file);
		if (resource != null) {
			for (IEditorReference eref : page.getEditorReferences()) {
				try {
					IFile open = eref.getEditorInput().getAdapter(IFile.class);
					if (open != null && open.equals(resource)) {
						Display.getDefault().asyncExec(() -> page.closeEditor(eref.getEditor(true), true));
					}
				} catch (PartInitException e) {
					handleException(e);
				}
			}
		}
	}

	public void refreshOpenEditors() {
		Display.getDefault().asyncExec(() -> {
			for (IEditorReference editor : PlatformUI.getWorkbench().getActiveWorkbenchWindow().getActivePage()
					.getEditorReferences()) {
				if (editor.getId().equals("org.integratedmodelling.kim.Kim")) {
					try {
						XtextEditor xte = EditorUtils.getXtextEditor(editor.getEditor(false));
						if (xte != null && !xte.isDirty()) {
							// leave it alone if dirty or we'll lose changes
							xte.setInput(xte.getEditorInput());
							// TODO REMEMBER THIS FOR REFACTORING
//							xte.getDocument().modify(new IUnitOfWork<Object, XtextResource>() {
//								@Override
//								public Object exec(XtextResource state) throws Exception {
//									return 0;
//								}
//							});
						}
					} catch (Exception e) {
						// poh
					}
				}
			}
		});
	}

	@SuppressWarnings("unchecked")
	public <T> Collection<T> chooseMany(String question, Collection<T> alternatives, Function<T, Image> imageProvider) {

		CheckedTreeSelectionDialog dialog = new CheckedTreeSelectionDialog(Eclipse.INSTANCE.getShell(),
				new LabelProvider() {

					@Override
					public Image getImage(Object element) {
						return imageProvider.apply((T) element);
					}
				}, new ITreeContentProvider() {

					@Override
					public boolean hasChildren(Object element) {
						return element instanceof Collection;
					}

					@Override
					public Object getParent(Object element) {
						return element instanceof Collection ? null : alternatives;
					}

					@Override
					public Object[] getElements(Object inputElement) {
						return getChildren(inputElement);
					}

					@Override
					public Object[] getChildren(Object parentElement) {
						return parentElement instanceof Collection ? alternatives.toArray() : null;
					}
				});

		dialog.setTitle("Choose one or more");
		dialog.setMessage(question);
		dialog.setInput(alternatives);
		List<T> ret = new ArrayList<T>();

		if (dialog.open() != Window.OK) {
			return ret;
		}
		Object[] result = dialog.getResult();
		for (Object o : result) {
			ret.add((T) o);
		}
		return ret;
	}

	public void error(Object message) {
		if (message instanceof Throwable) {
			handleException((Throwable) message);
		} else {
			StatusManager.getManager().handle(new Status(IStatus.ERROR, Activator.PLUGIN_ID, message.toString()));
		}
	}

	public void beep() {
		PlatformUI.getWorkbench().getDisplay().beep();
	}

	public void handleException(Throwable e) {
		if (e instanceof CoreException) {
			StatusManager.getManager().handle((CoreException) e, Activator.PLUGIN_ID);
		} else if (e instanceof KlabException) {
			alert(e.getMessage());
			StatusManager.getManager().handle(new Status(IStatus.ERROR, Activator.PLUGIN_ID, "Exception: ", e));
		} else {
			StatusManager.getManager().handle(new Status(IStatus.ERROR, Activator.PLUGIN_ID, "Exception: ", e));
		}
	}

	/**
	 * A more idiomatic getProject that will return null if the project does not
	 * exist.
	 * 
	 * @param name
	 * @return an Eclipse project or null
	 */
	public IProject getProject(String name) {
		IProject project = ResourcesPlugin.getWorkspace().getRoot().getProject(name);
		return project.exists() ? project : null;
	}

	public IProject[] getProjects() {
		return ResourcesPlugin.getWorkspace().getRoot().getProjects();
	}

	public IFile getIFile(File file) {
		IFile ret = null;
		try {
			IFile[] files = ResourcesPlugin.getWorkspace().getRoot()
					.findFilesForLocationURI(URIUtil.toURI(file.toURI().toURL()));
			if (files.length > 0) {
				ret = files[0];
			}
		} catch (MalformedURLException | URISyntaxException e) {
		}

		if (ret == null) {
			System.out.println("ZIOCAN IFILE IS NULL " + file);
		}
		return ret;
	}

	public File getFile(IFile file) {
		return file.getLocation().toFile();
	}

	// TODO substitute with a k.LAB marker type
	private static String XTEXT_MARKER_TYPE = "org.eclipse.xtext.ui.check.normal";

	private void addMarker(IFile file, String message, int lineNumber, int severity) {

		if (!file.exists()) {
			return;
		}

		try {

			System.out.println("Adding xtext marker: " + file + ":" + lineNumber + ":" + message);

			IMarker marker = file.createMarker(XTEXT_MARKER_TYPE);
			marker.setAttribute(IMarker.MESSAGE, message);
			marker.setAttribute(IMarker.SEVERITY, severity);
			if (lineNumber <= 0) {
				lineNumber = 1;
			}
			marker.setAttribute(IMarker.LINE_NUMBER, lineNumber);
		} catch (CoreException e) {
			handleException(e);
		}
	}

	/**
	 * Add all error and warning markers from k.LAB logical errors. Use XText marker
	 * types so they will be shown in editor. NOTE: only one marker per row is
	 * shown, and error supersede warnings. We could just remove the check and have
	 * the multiple markers thing, but at the moment errors may be reported more
	 * than once, and it's questionable that seeing multiple markers is more useful
	 * than fixing one and seeing the next afterwards.
	 * 
	 * @param ns
	 * @param file
	 * @throws CoreException
	 */
	public void updateMarkersForNamespace(final NamespaceCompilationResult report, final IFile file) {

		WorkspaceJob job = new WorkspaceJob("") {

			@Override
			public IStatus runInWorkspace(IProgressMonitor monitor) throws CoreException {

				if (file == null) {
					return Status.OK_STATUS;
				}

				if (file.exists()) {
					file.deleteMarkers(XTEXT_MARKER_TYPE, true, IResource.DEPTH_ZERO);
				}

				Activator.klab().resetCompileNotifications(report.getNamespaceId());

				for (CompileNotificationReference inot : report.getNotifications()) {

					System.out.println("COMPILE NOTIFICATION: " + inot);

					Activator.klab().recordCompileNotification(inot);

					if (inot.getLevel() == Level.SEVERE.intValue()) {
						addMarker(file, inot.getMessage(), inot.getFirstLine(), IMarker.SEVERITY_ERROR);
					} else if (inot.getLevel() == Level.WARNING.intValue()) {
						addMarker(file, inot.getMessage(), inot.getFirstLine(), IMarker.SEVERITY_WARNING);
					} else if (inot.getLevel() == Level.INFO.intValue()) {
						addMarker(file, inot.getMessage(), inot.getFirstLine(), IMarker.SEVERITY_INFO);
					}

				}
				return Status.OK_STATUS;
			}
		};
		job.setUser(false);
		job.schedule();
	}

	public void notification(final String label, final String description) {

		// TODO find a way to use those. So far all attempts were useless.
		System.out.println("NOTIFICATION: " + label + "\n" + description);

		// AbstractNotification notification = new AbstractNotification("klab.event") {
		//
		// public String getLabel() {
		// return label;
		// }
		//
		// public String getDescription() {
		// return description;
		// }
		//
		// @Override
		// public <T> T getAdapter(Class<T> adapter) {
		// // TODO Auto-generated method stub
		// return null;
		// }
		//
		// @Override
		// public Date getDate() {
		// // TODO Auto-generated method stub
		// return new Date();
		// }
		// };
		// NotificationsPlugin.getDefault().getService().notify(Collections.singletonList(notification));
	}

	public void copyToClipboard(String string) {
		if (string != null) {
			Toolkit toolkit = Toolkit.getDefaultToolkit();
			Clipboard clipboard = toolkit.getSystemClipboard();
			StringSelection strSel = new StringSelection(string);
			clipboard.setContents(strSel, null);
		} else {
			beep();
		}
	}

}

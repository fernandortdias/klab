package org.integratedmodelling.kim.model;

import java.net.URI;
import java.util.Collection;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.integratedmodelling.kim.api.IKimAnnotation;
import org.integratedmodelling.kim.api.IKimConcept;
import org.integratedmodelling.kim.api.IKimConcept.Type;
import org.integratedmodelling.kim.api.IKimConcept.Visitor;
import org.integratedmodelling.kim.api.IKimConceptStatement;
import org.integratedmodelling.kim.api.IKimMacro;
import org.integratedmodelling.kim.api.IKimMetadata;
import org.integratedmodelling.kim.api.IKimObservable;
import org.integratedmodelling.kim.api.IKimRestriction;
import org.integratedmodelling.kim.api.IKimScope;
import org.integratedmodelling.kim.api.IKimStatement;
import org.integratedmodelling.kim.kim.ConceptDeclaration;
import org.integratedmodelling.kim.model.Kim.ConceptDescriptor;
import org.integratedmodelling.kim.model.KimConceptStatement.ApplicableConceptImpl;
import org.integratedmodelling.kim.model.KimConceptStatement.ParentConcept;
import org.integratedmodelling.klab.utils.Pair;

public class KimMacro implements IKimMacro {

    class FieldTypeImpl implements FieldType {
        EnumSet<Type>     type     = EnumSet.noneOf(Type.class);
        ConceptDescriptor descriptor;
        boolean           optional = false;

        @Override
        public EnumSet<Type> getType() {
            return type;
        }

//        @Override
        public ConceptDescriptor getDescriptor() {
            return descriptor;
        }

        @Override
        public boolean isOptional() {
            return optional;
        }

        FieldTypeImpl(EnumSet<Type> type, ConceptDescriptor descriptor, boolean optional) {
            this.type.addAll(type);
            this.descriptor = descriptor;
            this.optional = optional;
        }
        
        FieldTypeImpl() {}
    }

    private static final long              serialVersionUID = 5951202536527381160L;
    private EnumSet<Field>                 fields           = EnumSet.noneOf(Field.class);
    private Map<Field, FieldType>          fieldTypes       = new HashMap<>();
    private Map<Field, ConceptDeclaration> declarations     = new HashMap<>();

    public KimMacro() {
    }

    public KimMacro(IKimConceptStatement statement) {
        setDelegate(statement);
    }

    private void setDelegate(IKimConceptStatement statement) {

        this.delegate = statement;

        /*
         * harvest fields and build type map
         */
        if (statement != null) {

            Visitor visitor = new Visitor() {

                @Override
                public void onReference(String conceptName, EnumSet<Type> type, IKimConcept validParent) {
                    if (conceptName.startsWith("$") || conceptName.startsWith("#")) {
                        Field field = Field.valueOf(Field.class, conceptName.substring(1).toUpperCase());
                        if (field != null) {
                            fields.add(field);
                            fieldTypes.put(field, new FieldTypeImpl(type, validParent == null ? null
                                    : Kim.INSTANCE.getConceptDescriptor(validParent.getName()), conceptName
                                            .startsWith("#")));
                        }
                    }
                }

                @Override
                public void onDeclaration(IKimConcept declaration) {
                }

                @Override
                public void onAuthority(String authority, String term) {
                }
            };

            statement.visitDeclarations(visitor);
        }
    }

    public boolean isEmpty() {
        return delegate == null;
    }

    @Override
    public Collection<Field> getFields() {
        return fields;
    }

    @Override
    public FieldType getType(Field field) {
        FieldType ret = fieldTypes.get(field);
        return ret == null ? new FieldTypeImpl() : ret;
    }

    public void setField(IKimMacro.Field field, ConceptDeclaration declaration) {
        declarations.put(field, declaration);
    }

//    @Override
    public ConceptDeclaration getDeclaration(Field field) {
        return declarations.get(field);
    }

    /*
     * -- delegation boilerplate below --
     */

    IKimConceptStatement delegate;

    public List<IKimScope> getChildren() {
        return delegate.getChildren();
    }

    public int hashCode() {
        return delegate.hashCode();
    }

    public int getFirstLine() {
        return delegate.getFirstLine();
    }

    public String getNamespace() {
        return delegate.getNamespace();
    }

    public int getLastLine() {
        return delegate.getLastLine();
    }

    public int getFirstCharOffset() {
        return delegate.getFirstCharOffset();
    }

    public String getName() {
        return delegate.getName();
    }

    public int getLastCharOffset() {
        return delegate.getLastCharOffset();
    }

    public boolean isMacro() {
        return delegate.isMacro();
    }

    public List<IKimAnnotation> getAnnotations() {
        return delegate.getAnnotations();
    }

    public IKimMetadata getMetadata() {
        return delegate.getMetadata();
    }

    public List<ApplicableConcept> getAppliesTo() {
        return ((KimConceptStatement)delegate).getAppliesTo();
    }

    public IKimMetadata getDocumentationMetadata() {
        return delegate.getDocumentationMetadata();
    }

    public boolean equals(Object obj) {
        return delegate.equals(obj);
    }

    public boolean isDeprecated() {
        return delegate.isDeprecated();
    }

    public String getDeprecation() {
        return delegate.getDeprecation();
    }

    public EnumSet<Type> getType() {
        return delegate.getType();
    }

    public String getUpperConceptDefined() {
        return delegate.getUpperConceptDefined();
    }

    public String getAuthorityDefined() {
        return delegate.getAuthorityDefined();
    }

    public String getAuthorityRequired() {
        return delegate.getAuthorityRequired();
    }

    public boolean isAbstract() {
        return delegate.isAbstract();
    }

    public boolean isAlias() {
        return delegate.isAlias();
    }

    public List<ParentConcept> getParents() {
        return ((KimConceptStatement)delegate).getParents();
    }

    public List<IKimRestriction> getRestrictions() {
        return delegate.getRestrictions();
    }

    public List<IKimConcept> getExposedTraits() {
        return delegate.getExposedTraits();
    }

    public List<IKimConcept> getRequiredIdentities() {
        return delegate.getRequiredIdentities();
    }

    public List<IKimConcept> getRequiredAttributes() {
        return delegate.getRequiredAttributes();
    }

    public List<IKimConcept> getRequiredRealms() {
        return delegate.getRequiredRealms();
    }

    public List<IKimConcept> getRequiredExtents() {
        return delegate.getRequiredExtents();
    }

    public List<IKimConcept> getTraitsInherited() {
        return delegate.getTraitsInherited();
    }

    public List<IKimConcept> getTraitsConferred() {
        return delegate.getTraitsConferred();
    }

    public List<IKimConcept> getPartParticipants() {
        return delegate.getPartParticipants();
    }

    public List<IKimConcept> getConstituentParticipants() {
        return delegate.getConstituentParticipants();
    }

    public String toString() {
        return delegate.toString();
    }

    public List<IKimConcept> getCountablesCreated() {
        return delegate.getCountablesCreated();
    }

    public List<ApplicableConcept> getSubjectsLinked() {
        return ((KimConceptStatement)delegate).getSubjectsLinked();
    }

    public List<IKimConcept> getQualitiesAffected() {
        return delegate.getQualitiesAffected();
    }

    public void set(IKimConceptStatement statement) {
        setDelegate(statement);
    }

    @Override
    public void visitDeclarations(Visitor visitor) {
        this.delegate.visitDeclarations(visitor);
    }

    @Override
    public String getAuthority() {
        return delegate.getAuthority();
    }

    @Override
    public String getAuthorityTerm() {
        return delegate.getAuthorityTerm();
    }

    @Override
    public List<IKimObservable> getTraitsExposed() {
        return delegate.getTraitsExposed();
    }

    @Override
    public boolean isDefiningExposedTraits() {
        return delegate.isDefiningExposedTraits();
    }

    @Override
    public List<Pair<IKimConcept, DescriptionType>> getObservablesDescribed() {
        return delegate.getObservablesDescribed();
    }

    @Override
    public String getLocationDescriptor() {
        return delegate.getLocationDescriptor();
    }

    @Override
    public List<IKimConcept> getConfigurationParticipants() {
        return delegate.getConfigurationParticipants();
    }

    @Override
    public String getSourceCode() {
      return delegate.getSourceCode();
    }

    @Override
    public IKimStatement getParent() {
        return delegate.getParent();
    }

	@Override
	public URI getURI() {
		return delegate.getURI();
	}
}

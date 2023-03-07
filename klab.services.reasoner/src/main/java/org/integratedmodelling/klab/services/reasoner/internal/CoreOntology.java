package org.integratedmodelling.klab.services.reasoner.internal;

import java.io.File;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import org.integratedmodelling.klab.api.exceptions.KIOException;
import org.integratedmodelling.klab.api.knowledge.KConcept;
import org.integratedmodelling.klab.api.knowledge.SemanticType;
import org.integratedmodelling.klab.api.services.KReasoner;
import org.integratedmodelling.klab.api.services.runtime.KChannel;
import org.integratedmodelling.klab.logging.Logging;
import org.integratedmodelling.klab.services.reasoner.owl.OWL;
import org.integratedmodelling.klab.utils.Utils;

/**
 * The core workspace only contains OWL ontologies and is read from the classpath.
 * 
 * @author ferdinando.villa
 *
 */
public class CoreOntology /* extends AbstractWorkspace */ {

    private boolean synced = false;
    private Map<SemanticType, KConcept> worldviewCoreConcepts = Collections.synchronizedMap(new HashMap<>());
    private File root;
    private static Map<SemanticType, String> coreConceptIds = Collections.synchronizedMap(new HashMap<>());

    public static final String CORE_ONTOLOGY_NAME = "odo-im";

    static {
        coreConceptIds.put(SemanticType.PROCESS, NS.CORE_PROCESS);
        coreConceptIds.put(SemanticType.SUBJECT, NS.CORE_SUBJECT);
        coreConceptIds.put(SemanticType.EVENT, NS.CORE_EVENT);
        coreConceptIds.put(SemanticType.FUNCTIONAL, NS.CORE_FUNCTIONAL_RELATIONSHIP);
        coreConceptIds.put(SemanticType.STRUCTURAL, NS.CORE_STRUCTURAL_RELATIONSHIP);
        coreConceptIds.put(SemanticType.RELATIONSHIP, NS.CORE_RELATIONSHIP);
        coreConceptIds.put(SemanticType.EXTENSIVE_PROPERTY, NS.CORE_EXTENSIVE_PHYSICAL_PROPERTY);
        coreConceptIds.put(SemanticType.INTENSIVE_PROPERTY, NS.CORE_INTENSIVE_PHYSICAL_PROPERTY);
        coreConceptIds.put(SemanticType.IDENTITY, NS.CORE_IDENTITY);
        coreConceptIds.put(SemanticType.ATTRIBUTE, NS.CORE_ATTRIBUTE);
        coreConceptIds.put(SemanticType.REALM, NS.CORE_REALM);
        coreConceptIds.put(SemanticType.ORDERING, NS.CORE_ORDERING);
        coreConceptIds.put(SemanticType.ROLE, NS.CORE_ROLE);
        coreConceptIds.put(SemanticType.CONFIGURATION, NS.CORE_CONFIGURATION);
        coreConceptIds.put(SemanticType.CLASS, NS.CORE_TYPE);
        coreConceptIds.put(SemanticType.QUANTITY, NS.CORE_QUANTITY);
        coreConceptIds.put(SemanticType.DOMAIN, NS.CORE_DOMAIN);
        coreConceptIds.put(SemanticType.ENERGY, NS.CORE_ENERGY);
        coreConceptIds.put(SemanticType.ENTROPY, NS.CORE_ENTROPY);
        coreConceptIds.put(SemanticType.LENGTH, NS.CORE_LENGTH);
        coreConceptIds.put(SemanticType.MASS, NS.CORE_MASS);
        coreConceptIds.put(SemanticType.VOLUME, NS.CORE_VOLUME);
        coreConceptIds.put(SemanticType.WEIGHT, NS.CORE_WEIGHT);
        coreConceptIds.put(SemanticType.MONEY, NS.CORE_MONETARY_VALUE);
        coreConceptIds.put(SemanticType.DURATION, NS.CORE_DURATION);
        coreConceptIds.put(SemanticType.AREA, NS.CORE_AREA);
        coreConceptIds.put(SemanticType.ACCELERATION, NS.CORE_ACCELERATION);
        coreConceptIds.put(SemanticType.PRIORITY, NS.CORE_PRIORITY);
        coreConceptIds.put(SemanticType.ELECTRIC_POTENTIAL, NS.CORE_ELECTRIC_POTENTIAL);
        coreConceptIds.put(SemanticType.CHARGE, NS.CORE_CHARGE);
        coreConceptIds.put(SemanticType.RESISTANCE, NS.CORE_RESISTANCE);
        coreConceptIds.put(SemanticType.RESISTIVITY, NS.CORE_RESISTIVITY);
        coreConceptIds.put(SemanticType.PRESSURE, NS.CORE_PRESSURE);
        coreConceptIds.put(SemanticType.ANGLE, NS.CORE_ANGLE);
        coreConceptIds.put(SemanticType.VELOCITY, NS.CORE_SPEED);
        coreConceptIds.put(SemanticType.TEMPERATURE, NS.CORE_TEMPERATURE);
        coreConceptIds.put(SemanticType.VISCOSITY, NS.CORE_VISCOSITY);
        coreConceptIds.put(SemanticType.AGENT, NS.CORE_AGENT);
        coreConceptIds.put(SemanticType.DELIBERATIVE, NS.CORE_DELIBERATIVE_AGENT);
        coreConceptIds.put(SemanticType.INTERACTIVE, NS.CORE_INTERACTIVE_AGENT);
        coreConceptIds.put(SemanticType.REACTIVE, NS.CORE_REACTIVE_AGENT);
        coreConceptIds.put(SemanticType.UNCERTAINTY, NS.CORE_UNCERTAINTY);
        coreConceptIds.put(SemanticType.PROBABILITY, NS.CORE_PROBABILITY);
        coreConceptIds.put(SemanticType.PROPORTION, NS.CORE_PROPORTION);
        coreConceptIds.put(SemanticType.NUMEROSITY, NS.CORE_COUNT);
        coreConceptIds.put(SemanticType.DISTANCE, NS.CORE_DISTANCE);
        coreConceptIds.put(SemanticType.RATIO, NS.CORE_RATIO);
        coreConceptIds.put(SemanticType.VALUE, NS.CORE_VALUE);
        coreConceptIds.put(SemanticType.CHANGE, NS.CORE_CHANGE);
        coreConceptIds.put(SemanticType.OCCURRENCE, NS.CORE_OCCURRENCE);
        coreConceptIds.put(SemanticType.PRESENCE, NS.CORE_PRESENCE);
        coreConceptIds.put(SemanticType.EXTENT, NS.CORE_EXTENT);
    }

    public static interface NS {

        // domain concepts for known extents
        public static final String SPACE_DOMAIN = "observation:Space";
        public static final String TIME_DOMAIN = "observation:Time";

        // core properties
        public static final String IS_ABSTRACT = "observation:isAbstract";
        public static final String BASE_DECLARATION = "observation:baseDeclaration";
        public static final String ORDER_PROPERTY = "observation:orderingRank";
        public static final String HAS_REALM_PROPERTY = "observation:hasRealm";
        public static final String HAS_IDENTITY_PROPERTY = "observation:hasIdentity";
        public static final String HAS_ATTRIBUTE_PROPERTY = "observation:hasAttribute";
        public static final String HAS_CONTEXT_PROPERTY = "observation:hasContext";
        public static final String HAS_COMPRESENT_PROPERTY = "observation:hasCompresent";
        public static final String HAS_CAUSANT_PROPERTY = "observation:hasCausant";
        public static final String HAS_CAUSED_PROPERTY = "observation:hasCaused";
        public static final String HAS_PURPOSE_PROPERTY = "observation:hasPurpose";
        public static final String OCCURS_DURING_PROPERTY = "observation:occursDuring";
        public static final String IS_ADJACENT_TO_PROPERTY = "observation:isAdjacentTo";
        public static final String HAS_SUBJECTIVE_TRAIT_PROPERTY = "observation:hasSubjectiveTrait";
        public static final String IS_SUBJECTIVE = "observation:isSubjectiveTrait";
        public static final String IS_INHERENT_TO_PROPERTY = "observation:isInherentTo";
        public static final String DESCRIBES_OBSERVABLE_PROPERTY = "observation:describesObservable";
        public static final String IS_COMPARED_TO_PROPERTY = "observation:isComparedTo";
        public static final String HAS_ROLE_PROPERTY = "observation:hasRole";
        public static final String INCARNATES_TRAIT_PROPERTY = "observation:exposesTrait";
        public static final String DENIABILITY_PROPERTY = "observation:isDeniable";
        public static final String IMPLIES_OBSERVABLE_PROPERTY = "observation:impliesObservable";
        public static final String IMPLIES_ROLE_PROPERTY = "observation:impliesRole";
        public static final String APPLIES_TO_PROPERTY = "observation:appliesTo";
        public static final String IMPLIES_SOURCE_PROPERTY = "observation:impliesSource";
        public static final String IMPLIES_DESTINATION_PROPERTY = "observation:impliesDestination";
        public static final String CONFERS_TRAIT_PROPERTY = "observation:confersTrait";
        public static final String DESCRIBES_QUALITY_PROPERTY = "observation:describesQuality";
        public static final String PROPORTIONAL_QUALITY_PROPERTY = "observation:proportionalQuality";
        public static final String INVERSELY_PROPORTIONAL_QUALITY_PROPERTY = "observation:inverselyProportionalQuality";
        public static final String CLASSIFIES_QUALITY_PROPERTY = "observation:classifiesQuality";
        public static final String REQUIRES_IDENTITY_PROPERTY = "observation:requiresIdentity";
        public static final String DISCRETIZES_QUALITY_PROPERTY = "observation:discretizesQuality";
        public static final String MARKS_QUALITY_PROPERTY = "observation:marksQuality";
        public static final String LIMITED_BY_PROPERTY = "observation:limitedBy";
        public static final String REPRESENTED_BY_PROPERTY = "observation:representedBy";
        public static final String IS_TYPE_DELEGATE = "observation:isTypeDelegate";
        public static final String IS_NEGATION_OF = "observation:isNegationOf";
        public static final String INHERENCY_IS_DISTRIBUTED = "observation:inherencyIsDistributed";
        public static final String IS_CORE_KIM_TYPE = "observation:isCoreKimType";

        // core observation ontology
        public static final String OBSERVATION = "observation:Observation";
        public static final String DIRECT_OBSERVATION = "observation:DirectObservation";
        public static final String INDIRECT_OBSERVATION = "observation:IndirectObservation";
        public static final String CLASSIFICATION = "observation:Classification";
        public static final String MEASUREMENT = "observation:Measurement";
        public static final String QUANTIFICATION = "observation:Quantification";
        public static final String RANKING = "observation:Ranking";
        public static final String COUNT_OBSERVATION = "observation:CountObservation";
        public static final String PERCENTAGE_OBSERVATION = "observation:PercentageObservation";
        public static final String PROPORTION_OBSERVATION = "observation:ProportionObservation";
        public static final String RATIO_OBSERVATION = "observation:RatioObservation";
        public static final String DISTANCE_OBSERVATION = "observation:DistanceMeasurement";
        public static final String VALUE_OBSERVATION = "observation:Valuation";
        public static final String PROBABILITY_OBSERVATION = "observation:ProbabilityObservation";
        public static final String UNCERTAINTY_OBSERVATION = "observation:UncertaintyObservation";
        public static final String PRESENCE_OBSERVATION = "observation:PresenceObservation";

        // contextual identities
        public static final String TEMPORAL_IDENTITY = "observation:TemporalIdentity";
        public static final String SPATIAL_IDENTITY = "observation:SpatialIdentity";
        public static final String PUNTAL_IDENTITY = "observation:Puntal";
        public static final String LINEAL_IDENTITY = "observation:Lineal";
        public static final String AREAL_IDENTITY = "observation:Areal";
        public static final String VOLUMETRIC_IDENTITY = "observation:Volumetric";
        public static final String YEARLY_IDENTITY = "observation:Yearly";
        public static final String MONTHLY_IDENTITY = "observation:Monthly";
        public static final String WEEKLY_IDENTITY = "observation:Weekly";
        public static final String DAILY_IDENTITY = "observation:Daily";
        public static final String HOURLY_IDENTITY = "observation:Hourly";

        // annotation property that specifies the base SI unit for a physical property
        public static final String SI_UNIT_PROPERTY = "observation:unit";

        /*
         * Annotations affecting the ranking system. Used as keys in maps, so they don't depend on
         * the ontology being in the system.
         */
        public static final String LEXICAL_SCOPE = "im:lexical-scope";
        public static final String TRAIT_CONCORDANCE = "im:trait-concordance";
        public static final String SEMANTIC_DISTANCE = "im:semantic-concordance";

        public static final String INHERENCY = "im:inherency";
        public static final String EVIDENCE = "im:evidence";
        public static final String NETWORK_REMOTENESS = "im:network-remoteness";
        public static final String SUBJECTIVE_CONCORDANCE = "im:subjective-concordance";

        // Scale criteria are an aggregation of time + space (and potentially others)
        public static final String SCALE_COVERAGE = "im:scale-coverage";
        public static final String SCALE_SPECIFICITY = "im:scale-specificity";
        public static final String SCALE_COHERENCY = "im:scale-coherency";

        /*
         * using space and time explicitly should be alternative to using scale criteria. All are
         * computed anyway and can be used together if wished.
         */
        public static final String SPACE_COVERAGE = "im:space-coverage";
        public static final String SPACE_SPECIFICITY = "im:space-specificity";
        public static final String SPACE_COHERENCY = "im:space-coherency";
        public static final String TIME_COVERAGE = "im:time-coverage";
        public static final String TIME_SPECIFICITY = "im:time-specificity";
        public static final String TIME_COHERENCY = "im:time-coherency";

        // only annotation used for subjective ranking in the default behavior
        public static final String RELIABILITY = "im:reliability";

        /*
         * annotation properties supporting k.LAB functions
         */
        public static final String CORE_OBSERVABLE_PROPERTY = "klab:coreObservable";
        public static final String CONCEPT_DEFINITION_PROPERTY = "klab:conceptDefinition";
        public static final String LOCAL_ALIAS_PROPERTY = "klab:localAlias";
        public static final String DISPLAY_LABEL_PROPERTY = "klab:displayLabel";
        public static final String REFERENCE_NAME_PROPERTY = "klab:referenceName";
        public static final String AUTHORITY_ID_PROPERTY = "klab:authorityId";
        public static final String UNTRANSFORMED_CONCEPT_PROPERTY = "klab:untransformedConceptId";
        public static final String ORIGINAL_TRAIT = "klab:originalTrait";

        /**
         * Annotation contains the ID of the property (in same ontology) that will be used to create
         * restrictions to adopt the trait carrying the annotation.
         */
        public static final String TRAIT_RESTRICTING_PROPERTY = "klab:restrictingProperty";

        /*
         * the core properties we use internally to establish observation semantics
         */
        /**
         * The property that links an observation to its observable.
         */
        public static final String CONTEXTUALIZES = "observation:contextualizes";
        public static final String INHERENT_IN = "observation:isInherentTo";
        public static final String OBSERVED_INTO = "observation:hasContext";
        public static final String PART_OF = "observation:isPartOf";
        public static final String CONSTITUENT_OF = "observation:isConstituentOf";
        public static final String STRUCTURING_PROPERTY = "observation:structuringObjectProperty";
        public static final String DEPENDS_ON_PROPERTY = "observation:dependsOn";
        public static final String RELATES_TO_PROPERTY = "observation:relatesTo";
        public static final String AFFECTS_PROPERTY = "observation:affects";
        public static final String CREATES_PROPERTY = "observation:creates";
        public static final String CHANGES_PROPERTY = "observation:changes";
        public static final String CHANGED_PROPERTY = "observation:changed";
        public static final String CONTAINS_PART_PROPERTY = "observation:containsPart";
        public static final String CONTAINS_PART_SPATIALLY_PROPERTY = "observation:containsPartSpatially";
        public static final String OBSERVES_PROPERTY = "observation:observes";

        /**
         * The ontology for all the core concepts (which depends only on BFO).
         */
        public static final String CORE_ONTOLOGY = "observation";

        /**
         * Only class that subsumes both observables and observations. It's bfo:entity in label.
         */
        public static final String CORE_PARTICULAR = "bfo:BFO_0000001";

        /**
         * Subsumes traits, domains and configurations. BFO does not still address universals, so we
         * provide it in observation.
         */
        public static final String CORE_UNIVERSAL = "observation:universal";

        /**
         * the root domain for the ontologies.
         */
        public static final String CORE_DOMAIN = "observation:Domain";
        public static final String CORE_VOID = "observation:Void";
        public static final String CORE_OBSERVABLE = "observation:Observable";
        public static final String CORE_OBSERVATION = "observation:Observation";
        public static final String CORE_OBJECT = "observation:DirectObservable";
        public static final String CORE_PROCESS = "observation:Process";
        public static final String CORE_QUALITY = "observation:Quality";
        public static final String CORE_EVENT = "observation:Event";
        public static final String CORE_TRAIT = "observation:Trait";
        public static final String CORE_IDENTITY = "observation:Identity";
        public static final String CORE_QUANTITY = "observation:ContinuousNumericallyQuantifiableQuality";
        public static final String CORE_ASSERTED_QUALITY = "observation:AssertedQuality";
        public static final String CORE_SUBJECT = "observation:Subject";
        public static final String CORE_PHYSICAL_OBJECT = "observation:PhysicalObject";
        public static final String CORE_PHYSICAL_PROPERTY = "observation:PhysicalProperty";
        public static final String CORE_EXTENSIVE_PHYSICAL_PROPERTY = "observation:ExtensivePhysicalProperty";
        public static final String CORE_INTENSIVE_PHYSICAL_PROPERTY = "observation:IntensivePhysicalProperty";
        public static final String CORE_ENERGY = "observation:Energy";
        public static final String CORE_ENTROPY = "observation:Entropy";
        public static final String CORE_LENGTH = "observation:Length";
        public static final String CORE_MASS = "observation:Mass";
        public static final String CORE_PROBABILITY = "observation:Probability";
        public static final String CORE_MAGNITUDE = "observation:Magnitude";
        public static final String CORE_LEVEL = "observation:Level";
        public static final String CORE_RELATIVE_QUANTITY = "observation:RelativeQuantity";
        public static final String CORE_VOLUME = "observation:Volume";
        public static final String CORE_WEIGHT = "observation:Weight";
        public static final String CORE_DURATION = "observation:Duration";
        public static final String CORE_MONETARY_VALUE = "observation:MonetaryValue";
        public static final String CORE_PREFERENCE_VALUE = "observation:PreferenceValue";
        public static final String CORE_ACCELERATION = "observation:Acceleration";
        public static final String CORE_AREA = "observation:Area";
        public static final String CORE_DENSITY = "observation:Density";
        public static final String CORE_ELECTRIC_POTENTIAL = "observation:ElectricPotential";
        public static final String CORE_CHARGE = "observation:Charge";
        public static final String CORE_RESISTANCE = "observation:Resistance";
        public static final String CORE_RESISTIVITY = "observation:Resistivity";
        public static final String CORE_PRESSURE = "observation:Pressure";
        public static final String CORE_ANGLE = "observation:Angle";
        public static final String CORE_ASSESSMENT = "observation:Assessment";
        public static final String CORE_CHANGE = "observation:Change";
        public static final String CORE_CHANGED_EVENT = "observation:ChangeEvent";
        public static final String CORE_CHANGE_RATE = "observation:ChangeRate";
        public static final String CORE_SPEED = "observation:Speed";
        public static final String CORE_TEMPERATURE = "observation:Temperature";
        public static final String CORE_VISCOSITY = "observation:Viscosity";
        public static final String CORE_AGENT = "observation:Agent";
        public static final String CORE_CONFIGURATION = "observation:Configuration";
        public static final String CORE_RELATIONSHIP = "observation:Relationship";
        public static final String CORE_FUNCTIONAL_RELATIONSHIP = "observation:FunctionalRelationship";
        public static final String CORE_STRUCTURAL_RELATIONSHIP = "observation:StructuralRelationship";
        public static final String CORE_TYPE = "observation:Type";
        public static final String CORE_ORDERING = "observation:Ordering";
        public static final String CORE_REALM = "observation:Realm";
        public static final String CORE_ATTRIBUTE = "observation:Attribute";
        public static final String CORE_ROLE = "observation:Role";
        public static final String CORE_PRIORITY = "observation:Priority";
        public static final String CORE_COUNT = "observation:Numerosity";
        public static final String CORE_PROPORTION = "observation:Proportion";
        public static final String CORE_RATIO = "observation:Ratio";
        public static final String CORE_PRESENCE = "observation:Presence";
        public static final String CORE_OCCURRENCE = "observation:Occurrence";
        public static final String CORE_VALUE = "observation:Value";
        public static final String CORE_DISTANCE = "observation:Distance";
        public static final String CORE_BASE_AGENT = "observation:Agent";
        public static final String CORE_REACTIVE_AGENT = "observation:ReactiveAgent";
        public static final String CORE_DELIBERATIVE_AGENT = "observation:DeliberativeAgent";
        public static final String CORE_INTERACTIVE_AGENT = "observation:InteractiveAgent";
        public static final String CORE_UNCERTAINTY = "observation:Uncertainty";
        public static final String CORE_OBSERVABILITY_TRAIT = "observation:Observability";
        public static final String CORE_PREDICTED_ATTRIBUTE = "observation:Predicted";
        public static final String CORE_ABSENCE_TRAIT = "observation:Absence";
        public static final String CORE_EXTENT = "observation:Extent";
        public static final String CORE_OBSERVATION_TRANSFORMATION = "observation:ObservationTransformation";
        public static final String CORE_MULTIPLICITY_REDUCTION = "observation:ObservationMultiplicityReduction";
    }

    public CoreOntology(File directory) {
        this.root = directory;
    }

    public void registerCoreConcept(String coreConcept, KConcept worldviewPeer) {
        /*
         * TODO must handle the specialized concepts so that they inherit from the redefined ones,
         * too. E.g. when the AGENT handler is received, it should create and install all the agent
         * types in the same ontology.
         */
    }

    // public IKimLoader load(IKimLoader loader, IMonitor monitor) {
    // load(monitor);
    // return loader;
    // }

    // @Override
    public /* IKimLoader */ void load(KChannel monitor) {
        // IKimLoader ret = null;
        if (!synced) {
            synced = true;
            Utils.Classpath.extractKnowledgeFromClasspath(this.root);
        }
        OWL.INSTANCE.initialize(this.root, monitor);

        /**
         * This test is unlikely to fail, but its purpose is primarily to preload the core ontology
         * catalogues, so that the k.IM validator will not cause delays when checking core concepts,
         * which makes the validator stop silently (by horrendous XText design) and ignore
         * everything beyond the first delay.
         * 
         * DO NOT REMOVE this test. Removing it will cause seemingly completely unrelated bugs that
         * will take a very long time to figure out.
         */
        KConcept dummy = OWL.INSTANCE.getConcept(NS.OBSERVATION);
        if (dummy == null) {
            throw new KIOException("core knowledge: can't find known concepts, ontologies are probably corrupted");
        }

        Logging.INSTANCE.info(OWL.INSTANCE.getOntologies(true).size() + " ontologies read from classpath");

        // return ret;
    }

    public KConcept getCoreType(Set<SemanticType> type) {

        if (type.contains(SemanticType.NOTHING)) {
            return OWL.INSTANCE.getNothing();
        }

        SemanticType coreType = getRepresentativeCoreSemanticType(type);
        if (coreType == null) {
            return null;
        }
        KConcept ret = worldviewCoreConcepts.get(coreType);
        if (ret == null) {
            String id = coreConceptIds.get(coreType);
            if (id != null) {
                ret = OWL.INSTANCE.getConcept(id);
            }
        }

        return ret;
    }

    public SemanticType getRepresentativeCoreSemanticType(Collection<SemanticType> type) {

        SemanticType ret = null;

        /*
         * FIXME can be made faster using a mask and a switch, although the specialized concepts
         * still require a bit of extra logic.
         */

        if (type.contains(SemanticType.PROCESS)) {
            ret = SemanticType.PROCESS;
        } else if (type.contains(SemanticType.SUBJECT)) {
            ret = SemanticType.SUBJECT;
        } else if (type.contains(SemanticType.EVENT)) {
            ret = SemanticType.EVENT;
        } else if (type.contains(SemanticType.RELATIONSHIP)) {
            ret = SemanticType.RELATIONSHIP;
        } else /* if (SemanticType.contains(SemanticType.TRAIT)) { */
        if (type.contains(SemanticType.IDENTITY)) {
            ret = SemanticType.IDENTITY;
        } else if (type.contains(SemanticType.ATTRIBUTE)) {
            ret = SemanticType.ATTRIBUTE;
        } else if (type.contains(SemanticType.REALM)) {
            ret = SemanticType.REALM;
        } else if (type.contains(SemanticType.ORDERING)) {
            ret = SemanticType.ORDERING;
        } else if (type.contains(SemanticType.ROLE)) {
            ret = SemanticType.ROLE;
        } else if (type.contains(SemanticType.CONFIGURATION)) {
            ret = SemanticType.CONFIGURATION;
        } else if (type.contains(SemanticType.CLASS)) {
            ret = SemanticType.CLASS;
        } else if (type.contains(SemanticType.QUANTITY)) {
            ret = SemanticType.QUANTITY;
        } else if (type.contains(SemanticType.DOMAIN)) {
            ret = SemanticType.DOMAIN;
        } else if (type.contains(SemanticType.ENERGY)) {
            ret = SemanticType.ENERGY;
        } else if (type.contains(SemanticType.ENTROPY)) {
            ret = SemanticType.ENTROPY;
        } else if (type.contains(SemanticType.LENGTH)) {
            ret = SemanticType.LENGTH;
        } else if (type.contains(SemanticType.MASS)) {
            ret = SemanticType.LENGTH;
        } else if (type.contains(SemanticType.VOLUME)) {
            ret = SemanticType.VOLUME;
        } else if (type.contains(SemanticType.WEIGHT)) {
            ret = SemanticType.WEIGHT;
        } else if (type.contains(SemanticType.MONEY)) {
            ret = SemanticType.MONEY;
        } else if (type.contains(SemanticType.DURATION)) {
            ret = SemanticType.DURATION;
        } else if (type.contains(SemanticType.AREA)) {
            ret = SemanticType.AREA;
        } else if (type.contains(SemanticType.ACCELERATION)) {
            ret = SemanticType.ACCELERATION;
        } else if (type.contains(SemanticType.PRIORITY)) {
            ret = SemanticType.PRIORITY;
        } else if (type.contains(SemanticType.ELECTRIC_POTENTIAL)) {
            ret = SemanticType.ELECTRIC_POTENTIAL;
        } else if (type.contains(SemanticType.CHARGE)) {
            ret = SemanticType.CHARGE;
        } else if (type.contains(SemanticType.RESISTANCE)) {
            ret = SemanticType.RESISTANCE;
        } else if (type.contains(SemanticType.RESISTIVITY)) {
            ret = SemanticType.RESISTIVITY;
        } else if (type.contains(SemanticType.PRESSURE)) {
            ret = SemanticType.PRESSURE;
        } else if (type.contains(SemanticType.ANGLE)) {
            ret = SemanticType.ANGLE;
        } else if (type.contains(SemanticType.VELOCITY)) {
            ret = SemanticType.VELOCITY;
        } else if (type.contains(SemanticType.TEMPERATURE)) {
            ret = SemanticType.TEMPERATURE;
        } else if (type.contains(SemanticType.VISCOSITY)) {
            ret = SemanticType.VISCOSITY;
        } else if (type.contains(SemanticType.AGENT)) {
            ret = SemanticType.AGENT;
        } else if (type.contains(SemanticType.UNCERTAINTY)) {
            ret = SemanticType.UNCERTAINTY;
        } else if (type.contains(SemanticType.PROBABILITY)) {
            ret = SemanticType.PROBABILITY;
        } else if (type.contains(SemanticType.PROPORTION)) {
            ret = SemanticType.PROPORTION;
        } else if (type.contains(SemanticType.NUMEROSITY)) {
            ret = SemanticType.NUMEROSITY;
        } else if (type.contains(SemanticType.DISTANCE)) {
            ret = SemanticType.DISTANCE;
        } else if (type.contains(SemanticType.RATIO)) {
            ret = SemanticType.RATIO;
        } else if (type.contains(SemanticType.VALUE)) {
            ret = SemanticType.VALUE;
        } else if (type.contains(SemanticType.MONETARY_VALUE)) {
            ret = SemanticType.MONETARY_VALUE;
        } else if (type.contains(SemanticType.OCCURRENCE)) {
            ret = SemanticType.OCCURRENCE;
        } else if (type.contains(SemanticType.PRESENCE)) {
            ret = SemanticType.PRESENCE;
        } else if (type.contains(SemanticType.EXTENT)) {
            ret = SemanticType.EXTENT;
        }
        // THESE COME AFTER ALL THE POSSIBLE SUBCLASSES
        else if (type.contains(SemanticType.EXTENSIVE_PROPERTY)) {
            ret = SemanticType.EXTENSIVE_PROPERTY;
        } else if (type.contains(SemanticType.INTENSIVE_PROPERTY)) {
            ret = SemanticType.INTENSIVE_PROPERTY;
        } /*
           * else if (type.contains(Type.ASSESSMENT)) { ret = Type.ASSESSMENT; }
           */

        return ret;
    }

    public String importOntology(String url, String prefix, KChannel monitor) {
        return OWL.INSTANCE.importExternal(url, prefix, monitor);
    }

    public void setAsCoreType(KConcept concept) {
        worldviewCoreConcepts.put(getRepresentativeCoreSemanticType(concept.getType()), concept);
    }

    public KConcept alignCoreInheritance(KConcept concept) {
        // if (concept.is(IKimConcept.Type.RELATIONSHIP)) {
        // // parent of core relationship depends on functional/structural nature
        // if (concept.is(IKimConcept.Type.FUNCTIONAL) ||
        // concept.is(IKimConcept.Type.STRUCTURAL)) {
        // concept = getCoreType(EnumSet.of(IKimConcept.Type.RELATIONSHIP));
        // }
        // } else if (concept.is(IKimConcept.Type.AGENT)) {
        // // parent of agent depends on agent typology
        // if (concept.is(IKimConcept.Type.DELIBERATIVE) ||
        // concept.is(IKimConcept.Type.INTERACTIVE)
        // || concept.is(IKimConcept.Type.REACTIVE)) {
        // concept = getCoreType(EnumSet.of(IKimConcept.Type.AGENT));
        // }
        // }
        return concept;
    }

//    /**
//     * Return the spatial nature, if any, of the passed concept, which should be a countable, or
//     * null.
//     * 
//     * @param concept
//     * @return
//     */
//    public ExtentDimension getSpatialNature(KConcept concept) {
//        for (KConcept identity : reasoner.identities(concept)) {
//            if (identity.is(OWL.INSTANCE.getConcept(NS.SPATIAL_IDENTITY))) {
//                if (identity.is(OWL.INSTANCE.getConcept(NS.AREAL_IDENTITY))) {
//                    return ExtentDimension.AREAL;
//                } else if (identity.is(OWL.INSTANCE.getConcept(NS.PUNTAL_IDENTITY))) {
//                    return ExtentDimension.PUNTAL;
//                }
//                if (identity.is(OWL.INSTANCE.getConcept(NS.LINEAL_IDENTITY))) {
//                    return ExtentDimension.LINEAL;
//                }
//                if (identity.is(OWL.INSTANCE.getConcept(NS.VOLUMETRIC_IDENTITY))) {
//                    return ExtentDimension.VOLUMETRIC;
//                }
//            }
//        }
//        return null;
//    }

//    /**
//     * Return the temporal resolution implied in the passed concept, which should be an event, or
//     * null.
//     * 
//     * TODO add the multiplier from (TBI) data properties associated with the identity.
//     * 
//     * @param concept
//     * @return
//     */
//    public KTime.Resolution getTemporalNature(KConcept concept) {
//        for (KConcept identity : reasoner.identities(concept)) {
//            if (identity.is(OWL.INSTANCE.getConcept(NS.TEMPORAL_IDENTITY))) {
//                if (identity.is(OWL.INSTANCE.getConcept(NS.YEARLY_IDENTITY))) {
//                    return Time.resolution(1, KTime.Resolution.Type.YEAR);
//                } else if (identity.is(OWL.INSTANCE.getConcept(NS.HOURLY_IDENTITY))) {
//                    return Time.resolution(1, KTime.Resolution.Type.HOUR);
//                } else if (identity.is(OWL.INSTANCE.getConcept(NS.WEEKLY_IDENTITY))) {
//                    return Time.resolution(1, KTime.Resolution.Type.WEEK);
//                } else if (identity.is(OWL.INSTANCE.getConcept(NS.MONTHLY_IDENTITY))) {
//                    return Time.resolution(1, KTime.Resolution.Type.MONTH);
//                } else if (identity.is(OWL.INSTANCE.getConcept(NS.DAILY_IDENTITY))) {
//                    return Time.resolution(1, KTime.Resolution.Type.DAY);
//                }
//            }
//        }
//        return null;
//    }

}

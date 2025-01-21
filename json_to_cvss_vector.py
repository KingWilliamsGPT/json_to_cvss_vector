"""JSON to cvss

This project simplifies the process of working with CVSS (Common Vulnerability Scoring System) by allowing you to input
 a JSON object instead of manually constructing a CVSS vector string. 
It supports **CVSS v2** and **CVSS v3** and provides a clean, type-safe interface using Pydantic for validation.
"""

import enum
from typing import Dict, Optional
from pydantic import BaseModel, Field, ConfigDict, root_validator, validator
from cvss import CVSS2, CVSS3  # Assuming the cvss library provides these classes


class Enum(str, enum.Enum): # trust me
    pass


class Enums():
    def __init__(self, enum_map: Dict[str, Enum]):
        self.enum_map = enum_map

    def __getattribute__(self, name):
        try:
            enum_map = object.__getattribute__(self, 'enum_map')
            attr = enum_map.get(name, None)  # same as self.enum.get but to avoid recursionss
            if attr is None:
                attr = super().__getattribute__(name)
        except AttributeError:
            # Handle missing attributes
            raise AttributeError(f"This Enum '{name}' is not registered with this instance.")
        return attr

    def get_enums(self):
        return self.enum_map


class Constants:
    def __init__(self, version: float = 3.1):
        self.version = version

        if version == 2:
            # print("CVSS2 calculator")
            from cvss.constants2 import (
                METRICS_ABBREVIATIONS,
                METRICS_ABBREVIATIONS_JSON,
                METRICS_MANDATORY,
                METRICS_VALUES,
                METRICS_VALUE_NAMES,
            )
        elif 3.0 <= version < 4.0:
            # print("CVSS3 calculator")
            from cvss.constants3 import (
                METRICS_ABBREVIATIONS,
                METRICS_ABBREVIATIONS_JSON,
                METRICS_MANDATORY,
                METRICS_VALUES,
                METRICS_VALUE_NAMES,
            )
        else:
            raise ValueError(f'Unknown version: {version}')

        self.METRICS_ABBREVIATIONS = METRICS_ABBREVIATIONS
        self.METRICS_ABBREVIATIONS_JSON = m_json = METRICS_ABBREVIATIONS_JSON
        self.METRICS_MANDATORY = METRICS_MANDATORY
        self.METRICS_VALUES = METRICS_VALUES
        self.METRICS_VALUE_NAMES = METRICS_VALUE_NAMES

        self.INVERTED_METRICS_ABBREVIATIONS_JSON = dict(zip(m_json.values(), m_json.keys()))
        self.INVERTED_METRICS_VALUE_NAMES = {
            k: dict(zip(v.values(), v.keys()))
            for k, v in self.METRICS_VALUE_NAMES.items()
        }

        self.enums = self.get_enums()


    def get_enums(self):
        enum_map = {}
        for abbr, json in self.METRICS_ABBREVIATIONS_JSON.items():
            metric_values_dict = {
                abbr_possible_values: self.METRICS_VALUE_NAMES[abbr][abbr_possible_values]
                for abbr_possible_values in self.METRICS_VALUES[abbr].keys()
            }
            enum = Enum(json, metric_values_dict)
            enum_map[json] = enum

        return Enums(enum_map)

    def is_mandatory(self, abbr):
        return abbr in self.METRICS_MANDATORY

    def abbr_to_json(self, abbr):
        return self.METRICS_ABBREVIATIONS_JSON[abbr]


_c2_contants = Constants(version=2)
_c3_contants = Constants(version=3)


def _validate(c: Constants, values: Dict[str, Optional[str]]) -> Dict[str, Optional[str]]:
    for json_attr, json_value  in values.items():
        abbr = c.INVERTED_METRICS_ABBREVIATIONS_JSON[json_attr]  # eg. AV, AC
        if c.is_mandatory(abbr) and json_value is None: # love the syntax here :)
            raise ValueError(f'The following fields are mandatory {[c.abbr_to_json(abbr) for abbr in c.METRICS_MANDATORY]} \ncheck {json_attr}:{json_value} or {abbr}:{json_value}\n\n\nRemediation: You may have forgotten "{json_attr}".\n\n')
    return values


class CVSS2Schema(BaseModel):
    accessVector: Optional[_c2_contants.enums.accessVector] = Field(default=None)
    accessComplexity: Optional[_c2_contants.enums.accessComplexity] = Field(default=None)
    authentication: Optional[_c2_contants.enums.authentication] = Field(default=None)
    confidentialityImpact: Optional[_c2_contants.enums.confidentialityImpact] = Field(default=None)
    integrityImpact: Optional[_c2_contants.enums.integrityImpact] = Field(default=None)
    availabilityImpact: Optional[_c2_contants.enums.availabilityImpact] = Field(default=None)
    exploitability: Optional[_c2_contants.enums.exploitability] = Field(default=None)
    remediationLevel: Optional[_c2_contants.enums.remediationLevel] = Field(default=None)
    reportConfidence: Optional[_c2_contants.enums.reportConfidence] = Field(default=None)
    collateralDamagePotential: Optional[_c2_contants.enums.collateralDamagePotential] = Field(default=None)
    targetDistribution: Optional[_c2_contants.enums.targetDistribution] = Field(default=None)
    confidentialityRequirement: Optional[_c2_contants.enums.confidentialityRequirement] = Field(default=None)
    integrityRequirement: Optional[_c2_contants.enums.integrityRequirement] = Field(default=None)
    availabilityRequirement: Optional[_c2_contants.enums.availabilityRequirement] = Field(default=None)

    @root_validator(skip_on_failure=True)
    def validate(cls, values):
        c = _c2_contants
        return _validate(c, values)


class CVSS3Schema(BaseModel):
    attackVector: Optional[_c3_contants.enums.attackVector] = Field(default=None)
    attackComplexity: Optional[_c3_contants.enums.attackComplexity] = Field(default=None)
    privilegesRequired: Optional[_c3_contants.enums.privilegesRequired] = Field(default=None)
    userInteraction: Optional[_c3_contants.enums.userInteraction] = Field(default=None)
    scope: Optional[_c3_contants.enums.scope] = Field(default=None)
    confidentialityImpact: Optional[_c3_contants.enums.confidentialityImpact] = Field(default=None)
    integrityImpact: Optional[_c3_contants.enums.integrityImpact] = Field(default=None)
    availabilityImpact: Optional[_c3_contants.enums.availabilityImpact] = Field(default=None)
    exploitCodeMaturity: Optional[_c3_contants.enums.exploitCodeMaturity] = Field(default=None)
    remediationLevel: Optional[_c3_contants.enums.remediationLevel] = Field(default=None)
    reportConfidence: Optional[_c3_contants.enums.reportConfidence] = Field(default=None)
    confidentialityRequirement: Optional[_c3_contants.enums.confidentialityRequirement] = Field(default=None)
    integrityRequirement: Optional[_c3_contants.enums.integrityRequirement] = Field(default=None)
    availabilityRequirement: Optional[_c3_contants.enums.availabilityRequirement] = Field(default=None)
    modifiedAttackVector: Optional[_c3_contants.enums.modifiedAttackVector] = Field(default=None)
    modifiedAttackComplexity: Optional[_c3_contants.enums.modifiedAttackComplexity] = Field(default=None)
    modifiedPrivilegesRequired: Optional[_c3_contants.enums.modifiedPrivilegesRequired] = Field(default=None)
    modifiedUserInteraction: Optional[_c3_contants.enums.modifiedUserInteraction] = Field(default=None)
    modifiedScope: Optional[_c3_contants.enums.modifiedScope] = Field(default=None)
    modifiedConfidentialityImpact: Optional[_c3_contants.enums.modifiedConfidentialityImpact] = Field(default=None)
    modifiedIntegrityImpact: Optional[_c3_contants.enums.modifiedIntegrityImpact] = Field(default=None)
    modifiedAvailabilityImpact: Optional[_c3_contants.enums.modifiedAvailabilityImpact] = Field(default=None)

    @root_validator(skip_on_failure=True)
    def validate(cls, values):
        c = _c3_contants
        return _validate(c, values)


def get_vector(values: Dict, version: float = 3.1):
    """
    Returns a cvss.CVSS[X] object.

    Args:
        version: The CVSS version (2.0, 3.0-3.9).
        values: A dictionary containing CVSS metric values. This should be validated
                using either CVSS2 or CVSS3, depending on the version.

    Returns:
        A cvss.CVSS[X] object representing the calculated CVSS score.

    Raises:
        ValueError: If the version is invalid or the input values fail validation.
    """
    # Validate the version
    v = int(version)
    if not (2 <= v < 4):
        raise ValueError(f"Unsupported CVSS version: {version}. Supported versions are 2.0, (3.0, 4.0]")

    if str(v).startswith('2'):
        v = 2

    coerced_version = float(v)
    head = f'CVSS:{coerced_version}/'

    # Validate the input values using the appropriate Pydantic model
    if v == 2:
        Schema = CVSS2Schema
        constants = _c2_contants
    else:
        Schema = CVSS3Schema
        constants = _c3_contants

    validated_values = Schema(**values).dict(exclude_none=True)

    # Convert the validated values into a CVSS vector string
    vector_parts = []
    for json_attr, value in validated_values.items():
        abbr = constants.INVERTED_METRICS_ABBREVIATIONS_JSON[json_attr]  # Get the abbreviation (e.g., "AV", "AC")
        value = constants.INVERTED_METRICS_VALUE_NAMES[abbr][value]
        vector_parts.append(f"{abbr}:{value}")

    cvss_vector = "/".join(vector_parts)

    # Create and return the appropriate CVSS object
    if v == 2:
        return CVSS2(cvss_vector)
    elif v == 3:
        return CVSS3(head+cvss_vector)



def test2():
    # METRICS_MANDATORY = ["AV", "AC", "Au", "C", "I", "A", ]
    d = {
        'accessVector': 'Local',
        'accessComplexity': 'High',
        'authentication': 'Multiple',
        'confidentialityImpact': 'None',
        'integrityImpact': 'None',
        'availabilityImpact': 'None',
    }

    return get_vector(version=2, values=d)


def test3():
    # METRICS_MANDATORY = ["AV", "AC", "PR", "UI", "S", "C", "I", "A"]
    d = {
        "attackVector": 'Network',
        "attackComplexity": 'Low',
        "privilegesRequired": 'None',
        "userInteraction": 'None',
        "scope": 'Changed',
        "confidentialityImpact": 'High',
        "integrityImpact": 'High',
        "availabilityImpact": 'High',
    }

    return get_vector(version=3, values=d)


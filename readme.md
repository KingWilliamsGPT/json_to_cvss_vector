# CVSS JSON to Vector Converter

This project simplifies the process of working with CVSS (Common Vulnerability Scoring System) by allowing you to input a JSON object instead of manually constructing a CVSS vector string. It supports **CVSS v2** and **CVSS v3** and provides a clean, type-safe interface using Pydantic for validation.

---

## Features

- **JSON to CVSS Vector Conversion**: Convert a JSON object into a valid CVSS vector string.
- **Validation**: Automatically validates input JSON against CVSS v2 or v3 schemas.
- **Type Safety**: Uses Pydantic models to ensure type safety and data integrity.
- **Support for CVSS v2 and v3**: Handles both CVSS v2 and v3 metrics seamlessly.

---

## Installation

To use this project, ensure you have Python 3.7+ installed. Then, install the required dependencies:

```bash
pip install pydantic cvss
```

---

## Usage

### 1. Import the Required Functions

```python
from cvss_json_converter import get_vector
```

### 2. Define Your JSON Input

For **CVSS v2**:

```python
cvss2_data = {
    'accessVector': 'Local',
    'accessComplexity': 'High',
    'authentication': 'Multiple',
    'confidentialityImpact': 'None',
    'integrityImpact': 'None',
    'availabilityImpact': 'None',
}
```

For **CVSS v3**:

```python
cvss3_data = {
    "attackVector": 'Network',
    "attackComplexity": 'Low',
    "privilegesRequired": 'None',
    "userInteraction": 'None',
    "scope": 'Changed',
    "confidentialityImpact": 'High',
    "integrityImpact": 'High',
    "availabilityImpact": 'High',
}
```

### 3. Convert JSON to CVSS Vector

For **CVSS v2**:

```python
cvss2_vector = get_vector(version=2, values=cvss2_data)
print(cvss2_vector)
```

For **CVSS v3**:

```python
cvss3_vector = get_vector(version=3, values=cvss3_data)
print(cvss3_vector)
```

---

## Example Output

### CVSS v2 Example

**Input**:
```python
cvss2_data = {
    'accessVector': 'Local',
    'accessComplexity': 'High',
    'authentication': 'Multiple',
    'confidentialityImpact': 'None',
    'integrityImpact': 'None',
    'availabilityImpact': 'None',
}
```

**Output**:
```
CVSS:2.0/AV:L/AC:H/Au:M/C:N/I:N/A:N
```

### CVSS v3 Example

**Input**:
```python
cvss3_data = {
    "attackVector": 'Network',
    "attackComplexity": 'Low',
    "privilegesRequired": 'None',
    "userInteraction": 'None',
    "scope": 'Changed',
    "confidentialityImpact": 'High',
    "integrityImpact": 'High',
    "availabilityImpact": 'High',
}
```

**Output**:
```
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H
```

---

## Error Handling

If the input JSON is invalid or missing mandatory fields, the library will raise a `ValueError` with a descriptive message. For example:

```python
try:
    cvss_vector = get_vector(version=3, values=invalid_data)
except ValueError as e:
    print(f"Error: {e}")
```

---

## Supported CVSS Metrics

### CVSS v2 Metrics
- `accessVector`
- `accessComplexity`
- `authentication`
- `confidentialityImpact`
- `integrityImpact`
- `availabilityImpact`
- `exploitability`
- `remediationLevel`
- `reportConfidence`
- `collateralDamagePotential`
- `targetDistribution`
- `confidentialityRequirement`
- `integrityRequirement`
- `availabilityRequirement`

### CVSS v3 Metrics
- `attackVector`
- `attackComplexity`
- `privilegesRequired`
- `userInteraction`
- `scope`
- `confidentialityImpact`
- `integrityImpact`
- `availabilityImpact`
- `exploitCodeMaturity`
- `remediationLevel`
- `reportConfidence`
- `confidentialityRequirement`
- `integrityRequirement`
- `availabilityRequirement`
- `modifiedAttackVector`
- `modifiedAttackComplexity`
- `modifiedPrivilegesRequired`
- `modifiedUserInteraction`
- `modifiedScope`
- `modifiedConfidentialityImpact`
- `modifiedIntegrityImpact`
- `modifiedAvailabilityImpact`

---

## Contributing

Contributions are welcome! If you find a bug or want to add a feature, please open an issue or submit a pull request.

---

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

---

## Acknowledgments

- [CVSS Library](https://github.com/ctxis/cvss) for providing the base CVSS calculation logic.
- [Pydantic](https://pydantic-docs.helpmanual.io/) for data validation and schema management.

---

## Contact

For questions or feedback, please open an issue on GitHub or contact the maintainer directly.

---

Enjoy using the CVSS JSON to Vector Converter! 🚀
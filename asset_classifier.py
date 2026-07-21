"""
Asset Classification from Cloud Tags
===================================
Detects production status, data sensitivity, and criticality from AWS/Azure tags.
"""

from typing import Optional, Dict, Any
from risk_scorer import AssetCriticality, DataSensitivity


class AwsAssetClassifier:
    """Classify AWS resources by tags."""

    # Tag keys that indicate production (case-insensitive)
    PROD_TAGS = {"environment", "env", "workload", "tier"}
    PROD_VALUES = {"prod", "production", "prd", "live", "critical"}

    # Tag keys for data sensitivity
    SENSITIVITY_TAGS = {"data_classification", "sensitivity", "pii", "regulated"}
    PII_VALUES = {"pii", "personal", "customer", "sensitive", "restricted"}
    FINANCIAL_VALUES = {"financial", "payment", "billing", "confidential"}

    @staticmethod
    def classify_by_tags(tags: Dict[str, str]) -> tuple:
        """
        Analyze resource tags to determine production status and data sensitivity.

        Args:
            tags: Dict of tag key-value pairs (from AWS resource)

        Returns:
            (is_production: bool, data_sensitivity: DataSensitivity)
        """
        if not tags:
            return False, DataSensitivity.PUBLIC

        # Normalize tags to lowercase for matching
        norm_tags = {k.lower(): v.lower() for k, v in tags.items()}

        # Check for production indicators
        is_production = any(
            (key in AwsAssetClassifier.PROD_TAGS and val in AwsAssetClassifier.PROD_VALUES)
            for key, val in norm_tags.items()
        )

        # Check for sensitivity indicators
        data_sensitivity = DataSensitivity.PUBLIC
        for key, val in norm_tags.items():
            if key in AwsAssetClassifier.SENSITIVITY_TAGS:
                if any(pii in val for pii in AwsAssetClassifier.PII_VALUES):
                    data_sensitivity = DataSensitivity.PII
                    break
                if any(fin in val for fin in AwsAssetClassifier.FINANCIAL_VALUES):
                    data_sensitivity = DataSensitivity.FINANCIAL
                    break
                if val in ("proprietary", "internal", "confidential"):
                    data_sensitivity = DataSensitivity.PROPRIETARY

        return is_production, data_sensitivity

    @staticmethod
    def classify_instance(instance_dict: Dict[str, Any]) -> tuple:
        """
        Classify an EC2 instance from its describe_instances output.

        Args:
            instance_dict: Instance dict from EC2 API

        Returns:
            (is_production: bool, data_sensitivity: DataSensitivity, has_public_ip: bool)
        """
        # Extract tags
        tags = {}
        for tag in instance_dict.get("Tags", []):
            tags[tag.get("Key", "")] = tag.get("Value", "")

        is_prod, sensitivity = AwsAssetClassifier.classify_by_tags(tags)

        # Check for public IP
        has_public_ip = bool(instance_dict.get("PublicIpAddress"))

        return is_prod, sensitivity, has_public_ip

    @staticmethod
    def classify_sg(sg_dict: Dict[str, Any]) -> tuple:
        """
        Classify a security group from its tags.

        Args:
            sg_dict: SecurityGroup dict from EC2 API

        Returns:
            (is_production: bool, data_sensitivity: DataSensitivity)
        """
        tags = {}
        for tag in sg_dict.get("Tags", []):
            tags[tag.get("Key", "")] = tag.get("Value", "")

        return AwsAssetClassifier.classify_by_tags(tags)

    @staticmethod
    def classify_by_name_heuristics(name: str) -> tuple:
        """
        Fallback: classify by resource name patterns when tags are absent.

        Args:
            name: Resource name or ID

        Returns:
            (is_production: bool, data_sensitivity: DataSensitivity)
        """
        if not name:
            return False, DataSensitivity.PUBLIC

        name_lower = name.lower()

        # Production indicators
        is_prod = any(
            indicator in name_lower
            for indicator in ("prod", "prd", "live", "critical", "-p-", "-prod-")
        )

        # Sensitivity indicators
        sensitivity = DataSensitivity.PUBLIC
        if any(s in name_lower for s in ("pii", "customer", "personal")):
            sensitivity = DataSensitivity.PII
        elif any(s in name_lower for s in ("payment", "billing", "financial")):
            sensitivity = DataSensitivity.FINANCIAL

        return is_prod, sensitivity


class AzureAssetClassifier:
    """Classify Azure resources by tags."""

    # Similar logic for Azure
    PROD_TAGS = {"environment", "env", "tier"}
    PROD_VALUES = {"prod", "production", "prd"}

    @staticmethod
    def classify_by_tags(tags: Optional[Dict[str, str]]) -> tuple:
        """Classify Azure resource by tags."""
        if not tags:
            return False, DataSensitivity.PUBLIC

        norm_tags = {k.lower(): v.lower() for k, v in tags.items()}

        is_production = any(
            (key in AzureAssetClassifier.PROD_TAGS and val in AzureAssetClassifier.PROD_VALUES)
            for key, val in norm_tags.items()
        )

        # Similar sensitivity check as AWS
        sensitivity = DataSensitivity.PUBLIC
        for key, val in norm_tags.items():
            if "sensitivity" in key or "classification" in key:
                if "pii" in val or "customer" in val:
                    sensitivity = DataSensitivity.PII
                    break
                if "payment" in val or "financial" in val:
                    sensitivity = DataSensitivity.FINANCIAL
                    break

        return is_production, sensitivity

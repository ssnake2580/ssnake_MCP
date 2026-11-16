# Copyright 2026 snmp-mcp contributors
# Licensed under the Apache License, Version 2.0 (see LICENSE)
"""OID constants for the IETF MIBs covered by v0.

We do NOT compile MIB files at runtime — the leaf OIDs we need are small
enough to hand-lift. This keeps the dependency footprint small (pysnmp
does not need its MIB compiler bundle) and makes the surface predictable.

See DESIGN.md §7 for the MIB-to-tool mapping.
"""

from __future__ import annotations

# --- SNMPv2-MIB (RFC 3418) ---------------------------------------------------
# Scalar group .1.3.6.1.2.1.1
SYS_DESCR = "1.3.6.1.2.1.1.1.0"
SYS_OBJECT_ID = "1.3.6.1.2.1.1.2.0"
SYS_UP_TIME = "1.3.6.1.2.1.1.3.0"
SYS_CONTACT = "1.3.6.1.2.1.1.4.0"
SYS_NAME = "1.3.6.1.2.1.1.5.0"
SYS_LOCATION = "1.3.6.1.2.1.1.6.0"
SYS_SERVICES = "1.3.6.1.2.1.1.7.0"

SYSTEM_GROUP = "1.3.6.1.2.1.1"

# --- IF-MIB (RFC 2863) -------------------------------------------------------
# ifNumber scalar
IF_NUMBER = "1.3.6.1.2.1.2.1.0"
# ifTable .1.3.6.1.2.1.2.2 — rows indexed by ifIndex
IF_TABLE = "1.3.6.1.2.1.2.2"
IF_INDEX = "1.3.6.1.2.1.2.2.1.1"
IF_DESCR = "1.3.6.1.2.1.2.2.1.2"
IF_TYPE = "1.3.6.1.2.1.2.2.1.3"
IF_MTU = "1.3.6.1.2.1.2.2.1.4"
IF_SPEED = "1.3.6.1.2.1.2.2.1.5"  # 32-bit Gauge32, saturates at ~4.29 Gbps
IF_PHYS_ADDRESS = "1.3.6.1.2.1.2.2.1.6"
IF_ADMIN_STATUS = "1.3.6.1.2.1.2.2.1.7"
IF_OPER_STATUS = "1.3.6.1.2.1.2.2.1.8"
IF_IN_OCTETS = "1.3.6.1.2.1.2.2.1.10"  # 32-bit Counter32
IF_IN_ERRORS = "1.3.6.1.2.1.2.2.1.14"
IF_IN_DISCARDS = "1.3.6.1.2.1.2.2.1.13"
IF_OUT_OCTETS = "1.3.6.1.2.1.2.2.1.16"  # 32-bit Counter32
IF_OUT_ERRORS = "1.3.6.1.2.1.2.2.1.20"
IF_OUT_DISCARDS = "1.3.6.1.2.1.2.2.1.19"
# ifXTable .1.3.6.1.2.1.31.1.1 — extensions (HC counters, ifName, ifAlias, ifHighSpeed)
IF_X_TABLE = "1.3.6.1.2.1.31.1.1"
IF_NAME = "1.3.6.1.2.1.31.1.1.1.1"
IF_HC_IN_OCTETS = "1.3.6.1.2.1.31.1.1.1.6"  # 64-bit Counter64
IF_HC_OUT_OCTETS = "1.3.6.1.2.1.31.1.1.1.10"  # 64-bit Counter64
IF_HIGH_SPEED = "1.3.6.1.2.1.31.1.1.1.15"  # in Mbps; 0 if unknown
IF_ALIAS = "1.3.6.1.2.1.31.1.1.1.18"

# ifAdminStatus / ifOperStatus enum values
IF_STATUS_NAMES = {
    1: "up",
    2: "down",
    3: "testing",
    4: "unknown",
    5: "dormant",
    6: "notPresent",
    7: "lowerLayerDown",
}

# Column-name mapping used by snmp_table for ifTable/ifXTable.
IF_TABLE_COLUMNS = {
    "1.3.6.1.2.1.2.2.1.1": "ifIndex",
    "1.3.6.1.2.1.2.2.1.2": "ifDescr",
    "1.3.6.1.2.1.2.2.1.3": "ifType",
    "1.3.6.1.2.1.2.2.1.4": "ifMtu",
    "1.3.6.1.2.1.2.2.1.5": "ifSpeed",
    "1.3.6.1.2.1.2.2.1.6": "ifPhysAddress",
    "1.3.6.1.2.1.2.2.1.7": "ifAdminStatus",
    "1.3.6.1.2.1.2.2.1.8": "ifOperStatus",
    "1.3.6.1.2.1.2.2.1.10": "ifInOctets",
    "1.3.6.1.2.1.2.2.1.13": "ifInDiscards",
    "1.3.6.1.2.1.2.2.1.14": "ifInErrors",
    "1.3.6.1.2.1.2.2.1.16": "ifOutOctets",
    "1.3.6.1.2.1.2.2.1.19": "ifOutDiscards",
    "1.3.6.1.2.1.2.2.1.20": "ifOutErrors",
}

IF_X_TABLE_COLUMNS = {
    "1.3.6.1.2.1.31.1.1.1.1": "ifName",
    "1.3.6.1.2.1.31.1.1.1.6": "ifHCInOctets",
    "1.3.6.1.2.1.31.1.1.1.10": "ifHCOutOctets",
    "1.3.6.1.2.1.31.1.1.1.15": "ifHighSpeed",
    "1.3.6.1.2.1.31.1.1.1.18": "ifAlias",
}

# --- HOST-RESOURCES-MIB (RFC 2790) -------------------------------------------
# Scalars
HR_SYSTEM_UPTIME = "1.3.6.1.2.1.25.1.1.0"
HR_SYSTEM_DATE = "1.3.6.1.2.1.25.1.2.0"
HR_SYSTEM_PROCESSES = "1.3.6.1.2.1.25.1.6.0"
HR_SYSTEM_NUM_USERS = "1.3.6.1.2.1.25.1.5.0"
HR_MEMORY_SIZE = "1.3.6.1.2.1.25.2.2.0"  # in KB
# hrStorageTable .1.3.6.1.2.1.25.2.3 — indexed by hrStorageIndex
HR_STORAGE_TABLE = "1.3.6.1.2.1.25.2.3"
HR_STORAGE_INDEX = "1.3.6.1.2.1.25.2.3.1.1"
HR_STORAGE_TYPE = "1.3.6.1.2.1.25.2.3.1.2"  # OID; see HR_STORAGE_TYPE_NAMES
HR_STORAGE_DESCR = "1.3.6.1.2.1.25.2.3.1.3"
HR_STORAGE_ALLOC_UNITS = "1.3.6.1.2.1.25.2.3.1.4"
HR_STORAGE_SIZE = "1.3.6.1.2.1.25.2.3.1.5"  # in alloc units
HR_STORAGE_USED = "1.3.6.1.2.1.25.2.3.1.6"
# hrProcessorTable .1.3.6.1.2.1.25.3.3 — indexed by hrDeviceIndex
HR_PROCESSOR_LOAD = "1.3.6.1.2.1.25.3.3.1.2"

HR_STORAGE_TABLE_COLUMNS = {
    "1.3.6.1.2.1.25.2.3.1.1": "hrStorageIndex",
    "1.3.6.1.2.1.25.2.3.1.2": "hrStorageType",
    "1.3.6.1.2.1.25.2.3.1.3": "hrStorageDescr",
    "1.3.6.1.2.1.25.2.3.1.4": "hrStorageAllocationUnits",
    "1.3.6.1.2.1.25.2.3.1.5": "hrStorageSize",
    "1.3.6.1.2.1.25.2.3.1.6": "hrStorageUsed",
}

# Common hrStorageType values (the OID under .1.3.6.1.2.1.25.2.1)
HR_STORAGE_TYPE_NAMES = {
    "1.3.6.1.2.1.25.2.1.1": "other",
    "1.3.6.1.2.1.25.2.1.2": "ram",
    "1.3.6.1.2.1.25.2.1.3": "virtual_memory",
    "1.3.6.1.2.1.25.2.1.4": "fixed_disk",
    "1.3.6.1.2.1.25.2.1.5": "removable_disk",
    "1.3.6.1.2.1.25.2.1.6": "floppy_disk",
    "1.3.6.1.2.1.25.2.1.7": "compact_disc",
    "1.3.6.1.2.1.25.2.1.8": "ram_disk",
    "1.3.6.1.2.1.25.2.1.9": "flash_memory",
    "1.3.6.1.2.1.25.2.1.10": "network_disk",
}

# --- PRINTER-MIB (RFC 3805) --------------------------------------------------
# Top-level .1.3.6.1.2.1.43
PRINTER_MIB_ROOT = "1.3.6.1.2.1.43"
# prtGeneralPrinterStatus is at prtGeneralEntry.2 (.1.3.6.1.2.1.43.5.1.1.2.<hrDeviceIndex>)
PRT_GENERAL_PRINTER_STATUS = "1.3.6.1.2.1.43.5.1.1.2"
# prtMarkerSuppliesTable .1.3.6.1.2.1.43.11.1 — indexed by hrDeviceIndex.prtMarkerSuppliesIndex
PRT_MARKER_SUPPLIES_TABLE = "1.3.6.1.2.1.43.11.1"
PRT_MARKER_SUPPLIES_INDEX = "1.3.6.1.2.1.43.11.1.1.1"
PRT_MARKER_SUPPLIES_MARKER_INDEX = "1.3.6.1.2.1.43.11.1.1.2"
PRT_MARKER_SUPPLIES_COLORANT_INDEX = "1.3.6.1.2.1.43.11.1.1.3"
PRT_MARKER_SUPPLIES_CLASS = "1.3.6.1.2.1.43.11.1.1.4"
PRT_MARKER_SUPPLIES_TYPE = "1.3.6.1.2.1.43.11.1.1.5"
PRT_MARKER_SUPPLIES_DESCRIPTION = "1.3.6.1.2.1.43.11.1.1.6"
PRT_MARKER_SUPPLIES_SUPPLY_UNIT = "1.3.6.1.2.1.43.11.1.1.7"
PRT_MARKER_SUPPLIES_MAX_CAPACITY = "1.3.6.1.2.1.43.11.1.1.8"
PRT_MARKER_SUPPLIES_LEVEL = "1.3.6.1.2.1.43.11.1.1.9"

PRT_MARKER_SUPPLIES_COLUMNS = {
    "1.3.6.1.2.1.43.11.1.1.1": "prtMarkerSuppliesIndex",
    "1.3.6.1.2.1.43.11.1.1.2": "prtMarkerSuppliesMarkerIndex",
    "1.3.6.1.2.1.43.11.1.1.3": "prtMarkerSuppliesColorantIndex",
    "1.3.6.1.2.1.43.11.1.1.4": "prtMarkerSuppliesClass",
    "1.3.6.1.2.1.43.11.1.1.5": "prtMarkerSuppliesType",
    "1.3.6.1.2.1.43.11.1.1.6": "prtMarkerSuppliesDescription",
    "1.3.6.1.2.1.43.11.1.1.7": "prtMarkerSuppliesSupplyUnit",
    "1.3.6.1.2.1.43.11.1.1.8": "prtMarkerSuppliesMaxCapacity",
    "1.3.6.1.2.1.43.11.1.1.9": "prtMarkerSuppliesLevel",
}

# prtMarkerSuppliesType (enum) — see RFC 3805 §4.5.2
PRT_SUPPLY_TYPE_NAMES = {
    1: "other",
    2: "unknown",
    3: "toner",
    4: "wasteToner",
    5: "ink",
    6: "inkCartridge",
    7: "inkRibbon",
    8: "wasteInk",
    9: "opc",  # photoconductor / drum
    10: "developer",
    11: "fuserOil",
    12: "solidWax",
    13: "ribbonWax",
    14: "wasteWax",
    15: "fuser",
    16: "coronaWire",
    17: "fuserOilWick",
    18: "cleanerUnit",
    19: "fuserCleaningPad",
    20: "transferUnit",
    21: "tonerCartridge",
    22: "fuserOiler",
    23: "water",
    24: "wasteWater",
    25: "glueWaterAdditive",
    26: "wastePaper",
    27: "bindingSupply",
    28: "bandingSupply",
    29: "stitchingWire",
    30: "shrinkWrap",
    31: "paperWrap",
    32: "staples",
    33: "inserts",
    34: "covers",
}

# prtMarkerSuppliesSupplyUnit (enum) — RFC 3805
PRT_SUPPLY_UNIT_NAMES = {
    1: "other",
    3: "tenThousandthsOfInches",
    4: "micrometers",
    7: "impressions",
    8: "sheets",
    11: "hours",
    12: "thousandthsOfOunces",
    13: "tenthsOfGrams",
    14: "hundrethsOfFluidOunces",
    15: "tenthsOfMilliliters",
    16: "feet",
    17: "meters",
    18: "items",
    19: "percent",
}

# prtInputTable .1.3.6.1.2.1.43.8.2 — input trays (paper)
PRT_INPUT_TABLE = "1.3.6.1.2.1.43.8.2"
PRT_INPUT_COLUMNS = {
    "1.3.6.1.2.1.43.8.2.1.1": "prtInputIndex",
    "1.3.6.1.2.1.43.8.2.1.2": "prtInputType",
    "1.3.6.1.2.1.43.8.2.1.5": "prtInputCapacityUnit",
    "1.3.6.1.2.1.43.8.2.1.9": "prtInputMaxCapacity",
    "1.3.6.1.2.1.43.8.2.1.10": "prtInputCurrentLevel",
    "1.3.6.1.2.1.43.8.2.1.11": "prtInputStatus",
    "1.3.6.1.2.1.43.8.2.1.12": "prtInputMediaName",
    "1.3.6.1.2.1.43.8.2.1.13": "prtInputName",
    "1.3.6.1.2.1.43.8.2.1.18": "prtInputMediaType",
}

# prtOutputTable .1.3.6.1.2.1.43.9.2 — output bins
PRT_OUTPUT_TABLE = "1.3.6.1.2.1.43.9.2"
PRT_OUTPUT_COLUMNS = {
    "1.3.6.1.2.1.43.9.2.1.1": "prtOutputIndex",
    "1.3.6.1.2.1.43.9.2.1.2": "prtOutputType",
    "1.3.6.1.2.1.43.9.2.1.4": "prtOutputCapacityUnit",
    "1.3.6.1.2.1.43.9.2.1.5": "prtOutputMaxCapacity",
    "1.3.6.1.2.1.43.9.2.1.6": "prtOutputRemainingCapacity",
    "1.3.6.1.2.1.43.9.2.1.7": "prtOutputStatus",
    "1.3.6.1.2.1.43.9.2.1.13": "prtOutputName",
}

# prtAlertTable .1.3.6.1.2.1.43.18.1 — active alerts
PRT_ALERT_TABLE = "1.3.6.1.2.1.43.18.1"
PRT_ALERT_COLUMNS = {
    "1.3.6.1.2.1.43.18.1.1.1": "prtAlertIndex",
    "1.3.6.1.2.1.43.18.1.1.2": "prtAlertSeverityLevel",
    "1.3.6.1.2.1.43.18.1.1.3": "prtAlertTrainingLevel",
    "1.3.6.1.2.1.43.18.1.1.4": "prtAlertGroup",
    "1.3.6.1.2.1.43.18.1.1.5": "prtAlertGroupIndex",
    "1.3.6.1.2.1.43.18.1.1.6": "prtAlertLocation",
    "1.3.6.1.2.1.43.18.1.1.7": "prtAlertCode",
    "1.3.6.1.2.1.43.18.1.1.8": "prtAlertDescription",
    "1.3.6.1.2.1.43.18.1.1.9": "prtAlertTime",
}

PRT_ALERT_SEVERITY_NAMES = {
    1: "other",
    3: "critical",
    4: "warning",
    5: "warningBinaryChangeEvent",
}

PRT_ALERT_TRAINING_NAMES = {
    1: "other",
    2: "unknown",
    3: "untrained",
    4: "trained",
    5: "fieldService",
    6: "management",
    7: "noInterventionRequired",
}

PRT_ALERT_GROUP_NAMES = {
    1: "other",
    3: "hostResourcesMIBStorageTable",
    4: "hostResourcesMIBDeviceTable",
    5: "generalPrinter",
    6: "cover",
    7: "localization",
    8: "input",
    9: "output",
    10: "marker",
    11: "markerSupplies",
    12: "markerColorant",
    13: "mediaPath",
    14: "channel",
    15: "interpreter",
    16: "consoleDisplayBuffer",
    17: "consoleLights",
    18: "alert",
    19: "finDevice",
    20: "finSupply",
    21: "finSupplyMediaInput",
}

# prtGeneralPrinterStatus enum
PRT_GENERAL_STATUS_NAMES = {
    1: "other",
    2: "unknown",
    3: "idle",
    4: "printing",
    5: "warmup",
}

# hrDeviceStatus enum (HOST-RESOURCES-MIB, used by some printers via prt linkage)
HR_DEVICE_STATUS_NAMES = {
    1: "unknown",
    2: "running",
    3: "warning",
    4: "testing",
    5: "down",
}

# --- Symbolic name resolution (used by snmp_get) -----------------------------
# Sparse table of well-known symbolic names → numeric OIDs. Extend as needed;
# we deliberately do NOT compile MIB files at runtime.
SYMBOLIC_OIDS: dict[str, str] = {
    "SNMPv2-MIB::sysDescr.0": SYS_DESCR,
    "SNMPv2-MIB::sysObjectID.0": SYS_OBJECT_ID,
    "SNMPv2-MIB::sysUpTime.0": SYS_UP_TIME,
    "SNMPv2-MIB::sysContact.0": SYS_CONTACT,
    "SNMPv2-MIB::sysName.0": SYS_NAME,
    "SNMPv2-MIB::sysLocation.0": SYS_LOCATION,
    "SNMPv2-MIB::sysServices.0": SYS_SERVICES,
    "IF-MIB::ifNumber.0": IF_NUMBER,
    "HOST-RESOURCES-MIB::hrSystemUptime.0": HR_SYSTEM_UPTIME,
    "HOST-RESOURCES-MIB::hrMemorySize.0": HR_MEMORY_SIZE,
}


def resolve_oid(oid: str) -> str:
    """Resolve a numeric or symbolic OID to its numeric dotted form.

    Numeric OIDs pass through unchanged. Symbolic OIDs are looked up in
    SYMBOLIC_OIDS; unknown symbolic names raise ValueError.
    """
    s = oid.strip()
    if not s:
        raise ValueError("empty OID")
    # Numeric form: only digits + dots (optional leading dot).
    if s.replace(".", "").isdigit() and any(c.isdigit() for c in s):
        return s.lstrip(".")
    # Symbolic form.
    if s in SYMBOLIC_OIDS:
        return SYMBOLIC_OIDS[s]
    raise ValueError(
        f"unknown symbolic OID {oid!r}; pass a numeric OID or add it to oids.SYMBOLIC_OIDS"
    )


# --- Enterprise OID vendor hints (for device_detect) -------------------------
# Maps the leading enterprise number under .1.3.6.1.4.1.<N> to a vendor name.
# Sourced from IANA Private Enterprise Numbers; not exhaustive.
ENTERPRISE_VENDOR_HINTS: dict[str, str] = {
    "9": "Cisco",
    "11": "Hewlett-Packard",
    "23": "Novell",
    "29": "Hughes",
    "41": "Western Digital",
    "42": "Sun Microsystems",
    "171": "D-Link",
    "207": "Allied Telesis",
    "232": "HP / Compaq",
    "236": "Samsung",
    "253": "Xerox",
    "311": "Microsoft",
    "318": "APC",
    "367": "Ricoh",
    "534": "Eaton / Powerware",
    "636": "Lantronix",
    "664": "Aruba Networks",
    "674": "Dell",
    "1248": "Seiko Epson",
    "1602": "Canon",
    "1991": "Foundry / Brocade",
    "2021": "Net-SNMP",
    "2435": "Brother",
    "2636": "Juniper",
    "4413": "Edgecore / Accton",
    "4526": "Netgear",
    "5528": "Nlyte / IBM",
    "6027": "Force10 / Dell",
    "6486": "Alcatel-Lucent",
    "6574": "Synology",
    "6876": "VMware",
    "8072": "Net-SNMP (extensions)",
    "8741": "OKI Data",
    "9303": "Vyatta",
    "10002": "Ubiquiti",
    "11129": "Google",
    "12356": "Fortinet",
    "14179": "Cisco / Airespace",
    "14525": "Meraki",
    "14823": "Aruba",
    "14988": "MikroTik",
    "16983": "TP-Link",
    "23695": "TP-Link (subsidiary)",
    "25506": "H3C",
    "30065": "Arista",
    "41112": "Ubiquiti UniFi",
    "57264": "Omada / TP-Link Business",
}


def vendor_from_sys_object_id(oid: str) -> str:
    """Return a best-effort vendor name from a sysObjectID enterprise number.

    Returns ``"unknown"`` if the OID does not start with the enterprise
    prefix or the number is not in our table.
    """
    prefix = "1.3.6.1.4.1."
    oid = oid.lstrip(".")
    if not oid.startswith(prefix):
        return "unknown"
    tail = oid[len(prefix) :]
    enterprise = tail.split(".", 1)[0]
    return ENTERPRISE_VENDOR_HINTS.get(enterprise, "unknown")

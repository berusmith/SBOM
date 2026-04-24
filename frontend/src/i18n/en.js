const en = {
  // ── Navigation ────────────────────────────────────────────────────────────
  nav: {
    dashboard:    "Dashboard",
    customers:    "Customers",
    riskOverview: "Risk Overview",
    policy:       "Policy",
    cra:          "CRA Incidents",
    tisax:        "TISAX",
    firmware:     "Firmware Scan",
    users:        "User Management",
    auditLog:     "Audit Log",
    settings:     "Settings",
    help:         "Help",
    search:       "Search components...",
    account:      "Account",
    logout:       "Logout",
  },

  // ── Common ────────────────────────────────────────────────────────────────
  common: {
    save:        "Save",
    cancel:      "Cancel",
    delete:      "Delete",
    edit:        "Edit",
    add:         "Add",
    confirm:     "Confirm",
    close:       "Close",
    loading:     "Loading...",
    uploading:   "Uploading...",
    scanning:    "Scanning...",
    analyzing:   "Analyzing...",
    generating:  "Generating...",
    submitting:  "Submitting...",
    saving:      "Saving...",
    success:     "Success",
    failed:      "Failed",
    unknown:     "Unknown",
    noData:      "No data",
    total:       "{{count}} records",
    back:        "Back",
    actions:     "Actions",
    status:      "Status",
    name:        "Name",
    version:     "Version",
    description: "Description",
    createdAt:   "Created",
    updatedAt:   "Updated",
    download:    "Download",
    export:      "Export",
    search:      "Search",
    filter:      "Filter",
    all:         "All",
    yes:         "Yes",
    no:          "No",
    na:          "N/A",
    copy:        "Copy",
    refresh:     "Refresh",
  },

  // ── Severity ──────────────────────────────────────────────────────────────
  severity: {
    critical: "Critical",
    high:     "High",
    medium:   "Medium",
    low:      "Low",
    info:     "Info",
    unknown:  "Unknown",
  },

  // ── VEX Status ────────────────────────────────────────────────────────────
  vexStatus: {
    open:         "Open",
    in_triage:    "In Triage",
    not_affected: "Not Affected",
    affected:     "Affected",
    fixed:        "Fixed",
  },

  // ── Reachability ──────────────────────────────────────────────────────────
  reachability: {
    function_reachable: "Function Confirmed",
    reachable:          "Imported",
    test_only:          "Test Only",
    not_found:          "Not Found",
    unknown:            "Not Analyzed",
  },

  // ── Login ─────────────────────────────────────────────────────────────────
  login: {
    title:     "SBOM Management Platform",
    username:  "Username",
    password:  "Password",
    submit:    "Login",
    loggingIn: "Logging in...",
    error:     "Invalid username or password",
  },

  // ── Dashboard ─────────────────────────────────────────────────────────────
  dashboard: {
    title:            "Dashboard",
    welcome:          "Welcome to SBOM Platform",
    craCountdown:     "CRA Enforcement Countdown",
    craDeadline:      "September 11, 2026",
    craDeadlineLabel: "EU CRA vulnerability reporting enforcement date",
    topThreats:       "Top 10 Unresolved Critical / High",
    scrollHint:       "← Scroll to see more",
    noStats:          "Unable to load statistics",
    severityDist:     "Severity Distribution",
    slaOverdue:       "SLA Overdue",
    patchStats:       "Patch Statistics",
    component:        "Component",
    product:          "Product / Release",
    customer:         "Customer",
    days:             "days",
    customers:        "Customers",
    products:         "Products",
    releases:         "Releases",
    components:       "Components",
    craActive:        "CRA Active",
    slaOverdue:       "SLA Overdue",
    vulnSeverityDist: "Vulnerability Severity",
    vulnStatus:       "Vulnerability Status",
    patchTracking:    "Patch Tracking",
    patchRate:        "Patch Rate",
    fixedVulns:       "Fixed Vulnerabilities",
    avgDaysToFix:     "Avg. Days to Fix",
    threatHighlights: "Threat Highlights",
    kevUnresolved:    "KEV {{n}} unresolved",
    noHighEpss:       "No high-EPSS vulnerabilities",
    viewerHint:       "Your vulnerability data is scoped to your organization.",
    viewerGoToProducts: "Go to Products →",
    noVulns:          "No vulnerabilities scanned yet. Upload an SBOM to start.",
  },

  // ── Organizations ─────────────────────────────────────────────────────────
  organizations: {
    title:         "Customer Management",
    add:           "Add Customer",
    name:          "Customer Name",
    contact:       "Contact",
    email:         "Email",
    noData:        "No customers yet. Click Add to create one.",
    deleteConfirm: "Delete this customer? All associated data will be removed.",
    viewProducts:  "View Products",
  },

  // ── Products ──────────────────────────────────────────────────────────────
  products: {
    title:        "Product Management",
    add:          "Add Product",
    name:         "Product Name",
    noData:       "No products yet",
    viewReleases: "View Releases",
    vulnTrend:    "Vulnerability Trend",
    showTrend:    "Show Trend Chart",
  },

  // ── Releases ──────────────────────────────────────────────────────────────
  releases: {
    title:    "Release Management",
    add:      "Add Release",
    version:  "Version",
    noData:   "No releases yet",
    locked:   "Locked",
    unlocked: "Unlocked",
  },

  // ── ReleaseDetail ─────────────────────────────────────────────────────────
  releaseDetail: {
    tabs: {
      components: "Components",
      vulns:      "Vulnerabilities",
      depGraph:   "Dependency Graph",
    },
    upload: {
      label:      "Upload SBOM File",
      hint:       "Supports CycloneDX JSON and SPDX JSON",
      selectFile: "Select File",
      uploading:  "Uploading...",
      success:    "Done: {{components}} components, {{vulns}} vulnerabilities",
      failed:     "Failed: {{msg}}",
      diff: {
        prev:        "vs.",
        compAdded:   "+{{n}} components",
        compRemoved: "-{{n}} components",
        vulnAdded:   "+{{n}} vulns",
        vulnRemoved: "-{{n}} vulns",
        noChange:    "No changes",
      },
    },
    actions: {
      rescan:         "Rescan CVEs",
      rescanning:     "Scanning...",
      downloadReport: "Download PDF Report",
      lockVersion:    "Lock Release",
      unlockVersion:  "Unlock Release",
      exportCsv:      "Export CSV",
      exportCdx:      "Export CycloneDX XML",
      exportSpdx:     "Export SPDX JSON",
      scanImage:      "Scan Container Image",
      scanIac:        "Scan IaC (zip)",
      reachability:   "Reachability Analysis (zip)",
      enrichGhsa:     "Enrich GHSA Data",
      enrichNvd:      "Update NVD Data",
      enrichEpss:     "Update EPSS Scores",
      checkIntegrity: "Verify Integrity",
      advanced:       "Advanced",
    },
    components: {
      name:        "Component",
      version:     "Version",
      license:     "License",
      licenseRisk: "License Risk",
      vulnCount:   "Vulns",
      maxSeverity: "Max Severity",
      noSbom:      "No SBOM uploaded yet",
    },
    vulns: {
      cveId:          "CVE ID",
      component:      "Component",
      cvss:           "CVSS",
      severity:       "Severity",
      epss:           "EPSS",
      sla:            "SLA",
      reachability:   "Reachability",
      vexStatus:      "VEX Status",
      actions:        "Actions",
      noVulns:        "No vulnerabilities found",
      overdue:        "{{n}}d overdue",
      warningDays:    "{{n}}d left",
      okDays:         "{{n}}d",
      suppress:       "Suppress",
      unsuppress:     "Unsuppress",
      showSuppressed: "Show Suppressed",
      hideSuppressed: "Hide Suppressed",
    },
    gate: {
      title:  "Policy Gate",
      passed: "Passed",
      failed: "Failed",
    },
    locked:      "This release is locked. SBOM upload, rescan, and VEX edits are disabled.",
    lockConfirm: "Lock this release? Upload, rescan, and VEX edits will be disabled. Confirm?",
  },

  // ── Vulnerabilities ───────────────────────────────────────────────────────
  vulns: {
    batchUpdate: "Batch Update",
    setStatus:   "Set Status",
    selected:    "{{n}} selected",
    history:     "History",
    noHistory:   "No history yet",
    description: "NVD description not yet enriched. Click Update NVD.",
    references:  "References",
    cwe:         "CWE",
    cvssV3:      "CVSS v3",
    cvssV4:      "CVSS v4",
    ghsa:        "GHSA",
  },

  // ── SLA ───────────────────────────────────────────────────────────────────
  sla: {
    overdue: "Overdue",
    warning: "Due Soon",
    ok:      "OK",
    na:      "N/A",
  },

  // ── CRA Countdown ─────────────────────────────────────────────────────────
  craCountdown: {
    urgent:       "Urgent",
    warning:      "Warning",
    reminder:     "Reminder",
    deadline:     "EU CRA Article 14 enforcement date: ",
    deadlineDate: "September 11, 2026",
    days:         "days",
  },

  // ── CRA ───────────────────────────────────────────────────────────────────
  cra: {
    title:      "CRA Incident Management",
    add:        "New Incident",
    incident:   "Incident",
    status:     "Status",
    startClock: "Start Clock",
    advance:    "Advance",
    close:      "Close",
    noData:     "No incidents yet",
  },

  // ── TISAX ─────────────────────────────────────────────────────────────────
  tisax: {
    title:    "TISAX Self-Assessment",
    add:      "New Assessment",
    maturity: "Maturity",
    controls: "Controls",
    gap:      "Gap Analysis",
    noData:   "No assessments yet",
  },

  // ── Settings ──────────────────────────────────────────────────────────────
  settings: {
    title:   "Notification Settings",
    brand:   "Brand Settings",
    alerts:  "Alert Settings",
    webhook: "Webhook URL",
    email:   "Email Notifications",
    test:    "Test",
    save:    "Save Settings",
  },

  // ── Users ─────────────────────────────────────────────────────────────────
  users: {
    title:    "User Management",
    add:      "Add User",
    username: "Username",
    role:     "Role",
    admin:    "Admin",
    viewer:   "Viewer",
    noData:   "No users yet",
  },

  // ── Search ────────────────────────────────────────────────────────────────
  search: {
    title:       "Global Component Search",
    placeholder: "Search component name or CVE ID...",
    noResults:   "No results found",
    component:   "Component",
    product:     "Product",
    release:     "Release",
    vulnCount:   "Vulns",
  },

  // ── Firmware ──────────────────────────────────────────────────────────────
  firmware: {
    title:      "Firmware Scan",
    upload:     "Upload Firmware",
    scanning:   "Scanning",
    completed:  "Completed",
    failed:     "Failed",
    components: "Components",
    noScans:    "No scan records yet",
  },

  // ── Help ──────────────────────────────────────────────────────────────────
  help: {
    title:     "Help Center",
    search:    "Search articles...",
    noResults: "No articles found",
  },

  // ── Audit Log ─────────────────────────────────────────────────────────────
  activity: {
    title:     "Audit Log",
    dateFrom:  "From",
    dateTo:    "To",
    export:    "Export CSV",
    noData:    "No records",
    action:    "Action",
    user:      "User",
    resource:  "Resource",
    timestamp: "Timestamp",
  },

  // ── License Risk ──────────────────────────────────────────────────────────
  licenseRisk: {
    permissive: "Permissive",
    copyleft:   "Copyleft",
    commercial: "Commercial",
    unknown:    "Unknown",
  },
};

export default en;

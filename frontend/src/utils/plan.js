/**
 * Plan utilities for frontend feature gating.
 * Plans: starter < standard < professional
 */

const PLAN_RANK = { starter: 0, standard: 1, professional: 2 };

export function getPlan() {
  const role = localStorage.getItem("role");
  if (role === "admin") return "professional"; // admin always has full access
  return localStorage.getItem("plan") || "starter";
}

export function hasPlan(required) {
  const current = getPlan();
  return (PLAN_RANK[current] ?? 0) >= (PLAN_RANK[required] ?? 0);
}

export const PLAN_LABEL = {
  starter:      "Starter",
  standard:     "Standard",
  professional: "Professional",
};

export const PLAN_COLOR = {
  starter:      "bg-gray-100 text-gray-600",
  standard:     "bg-blue-100 text-blue-700",
  professional: "bg-purple-100 text-purple-700",
};

// Features and their minimum plan
export const FEATURE_PLAN = {
  cra:        "standard",
  iec4_1:     "standard",
  epss:       "standard",
  ghsa:       "standard",
  monitor:    "standard",
  convert:    "standard",
  iec4_2:     "professional",
  iec3_3:     "professional",
  tisax:      "professional",
  reachability: "professional",
  signature:  "professional",
  trivy:      "professional",
};

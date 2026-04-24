import { lazy, Suspense } from "react";
import { BrowserRouter, Navigate, Routes, Route } from "react-router-dom";
import Layout from "./components/Layout";
import { ToastProvider } from "./components/Toast";
import Login from "./pages/Login";

const Dashboard         = lazy(() => import("./pages/Dashboard"));
const Organizations     = lazy(() => import("./pages/Organizations"));
const Products          = lazy(() => import("./pages/Products"));
const Releases          = lazy(() => import("./pages/Releases"));
const ReleaseDetail     = lazy(() => import("./pages/ReleaseDetail"));
const CRAIncidents      = lazy(() => import("./pages/CRAIncidents"));
const CRAIncidentDetail = lazy(() => import("./pages/CRAIncidentDetail"));
const Search            = lazy(() => import("./pages/Search"));
const ReleaseDiff       = lazy(() => import("./pages/ReleaseDiff"));
const Settings          = lazy(() => import("./pages/Settings"));
const RiskOverview      = lazy(() => import("./pages/RiskOverview"));
const Policies          = lazy(() => import("./pages/Policies"));
const Help              = lazy(() => import("./pages/Help"));
const AdminActivity     = lazy(() => import("./pages/AdminActivity"));
const TISAXAssessments  = lazy(() => import("./pages/TISAXAssessments"));
const TISAXDetail       = lazy(() => import("./pages/TISAXDetail"));
const Profile           = lazy(() => import("./pages/Profile"));
const Users             = lazy(() => import("./pages/Users"));
const FirmwareUpload    = lazy(() => import("./pages/FirmwareUpload"));
const ForgotPassword    = lazy(() => import("./pages/ForgotPassword"));
const ResetPassword     = lazy(() => import("./pages/ResetPassword"));

function RequireAuth({ children }) {
  const token = localStorage.getItem("token");
  if (!token) return <Navigate to="/login" replace />;
  return children;
}

function RequireAdmin({ children }) {
  const role = localStorage.getItem("role");
  if (role !== "admin") return <Navigate to="/" replace />;
  return children;
}

function ViewerOrgRedirect() {
  const orgId = localStorage.getItem("org_id");
  const role = localStorage.getItem("role");
  if (role !== "admin" && orgId) return <Navigate to={`/organizations/${orgId}/products`} replace />;
  return <Organizations />;
}

function PageLoading() {
  return (
    <div className="flex items-center justify-center p-10 text-gray-600 text-sm">
      載入中...
    </div>
  );
}

export default function App() {
  return (
    <ToastProvider>
    <BrowserRouter future={{ v7_relativeSplatPath: true, v7_startTransition: true }}>
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route path="/forgot-password" element={<ForgotPassword />} />
        <Route path="/reset-password" element={<ResetPassword />} />
        <Route
          path="/*"
          element={
            <RequireAuth>
              <Layout>
                <Suspense fallback={<PageLoading />}>
                <Routes>
                  <Route path="/" element={<Dashboard />} />
                  <Route path="/organizations" element={<ViewerOrgRedirect />} />
                  <Route path="/organizations/:orgId/products" element={<Products />} />
                  <Route path="/products/:productId/releases" element={<Releases />} />
                  <Route path="/releases/:releaseId" element={<ReleaseDetail />} />
                  <Route path="/cra" element={<CRAIncidents />} />
                  <Route path="/cra/:incidentId" element={<CRAIncidentDetail />} />
                  <Route path="/search" element={<Search />} />
                  <Route path="/releases/diff" element={<ReleaseDiff />} />
                  <Route path="/settings" element={<RequireAdmin><Settings /></RequireAdmin>} />
                  <Route path="/risk-overview" element={<RiskOverview />} />
                  <Route path="/policies" element={<Policies />} />
                  <Route path="/help" element={<Help />} />
                  <Route path="/admin/activity" element={<RequireAdmin><AdminActivity /></RequireAdmin>} />
                  <Route path="/tisax" element={<TISAXAssessments />} />
                  <Route path="/tisax/:assessmentId" element={<TISAXDetail />} />
                  <Route path="/profile" element={<Profile />} />
                  <Route path="/admin/users" element={<RequireAdmin><Users /></RequireAdmin>} />
                  <Route path="/firmware" element={<FirmwareUpload />} />
                </Routes>
                </Suspense>
              </Layout>
            </RequireAuth>
          }
        />
      </Routes>
    </BrowserRouter>
    </ToastProvider>
  );
}

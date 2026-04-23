import { BrowserRouter, Navigate, Routes, Route } from "react-router-dom";
import Layout from "./components/Layout";
import { ToastProvider } from "./components/Toast";
import Login from "./pages/Login";
import Dashboard from "./pages/Dashboard";
import Organizations from "./pages/Organizations";
import Products from "./pages/Products";
import Releases from "./pages/Releases";
import ReleaseDetail from "./pages/ReleaseDetail";
import CRAIncidents from "./pages/CRAIncidents";
import CRAIncidentDetail from "./pages/CRAIncidentDetail";
import Search from "./pages/Search";
import ReleaseDiff from "./pages/ReleaseDiff";
import Settings from "./pages/Settings";
import RiskOverview from "./pages/RiskOverview";
import Policies from "./pages/Policies";
import Help from "./pages/Help";
import AdminActivity from "./pages/AdminActivity";
import TISAXAssessments from "./pages/TISAXAssessments";
import TISAXDetail from "./pages/TISAXDetail";
import Profile from "./pages/Profile";
import Users from "./pages/Users";
import FirmwareUpload from "./pages/FirmwareUpload";

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

export default function App() {
  return (
    <ToastProvider>
    <BrowserRouter>
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route
          path="/*"
          element={
            <RequireAuth>
              <Layout>
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
              </Layout>
            </RequireAuth>
          }
        />
      </Routes>
    </BrowserRouter>
    </ToastProvider>
  );
}

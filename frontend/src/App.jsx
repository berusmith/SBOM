import { BrowserRouter, Navigate, Routes, Route } from "react-router-dom";
import Layout from "./components/Layout";
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

function RequireAuth({ children }) {
  const token = localStorage.getItem("token");
  if (!token) return <Navigate to="/login" replace />;
  return children;
}

export default function App() {
  return (
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
                  <Route path="/organizations" element={<Organizations />} />
                  <Route path="/organizations/:orgId/products" element={<Products />} />
                  <Route path="/products/:productId/releases" element={<Releases />} />
                  <Route path="/releases/:releaseId" element={<ReleaseDetail />} />
                  <Route path="/cra" element={<CRAIncidents />} />
                  <Route path="/cra/:incidentId" element={<CRAIncidentDetail />} />
                  <Route path="/search" element={<Search />} />
                  <Route path="/releases/diff" element={<ReleaseDiff />} />
                  <Route path="/settings" element={<Settings />} />
                </Routes>
              </Layout>
            </RequireAuth>
          }
        />
      </Routes>
    </BrowserRouter>
  );
}

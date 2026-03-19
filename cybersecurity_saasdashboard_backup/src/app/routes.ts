import { createBrowserRouter } from "react-router";

import RequireAuth from "./components/auth/RequireAuth";
import AppLayout from "./layouts/AppLayout";
import Dashboard from "./pages/Dashboard";
import Login from "./pages/Login";
import NewScan from "./pages/NewScan";
import ScanResults from "./pages/ScanResults";

export const router = createBrowserRouter([
  {
    path: "/login",
    Component: Login,
  },
  {
    Component: RequireAuth,
    children: [
      {
        path: "/",
        Component: AppLayout,
        children: [
          { index: true, Component: Dashboard },
          { path: "new-scan", Component: NewScan },
          { path: "scan/:id", Component: ScanResults },
        ],
      },
    ],
  },
]);

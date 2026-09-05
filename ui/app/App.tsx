import React from "react";
import { Route, Routes } from "react-router-dom";
import { IamSankey } from "./pages/IamSankey";

/**
 * Root app — no PageLayout shell so the 3-column visualizer can fill the
 * entire viewport without fighting Strato's built-in overflow / padding.
 */
export const App = () => (
  <Routes>
    <Route path="/*" element={<IamSankey />} />
  </Routes>
);

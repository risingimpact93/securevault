import { useEffect, useState } from "react";
import { appBuild } from "../api";

export default function BuildStamp() {
  const [label, setLabel] = useState("SecureVault");

  useEffect(() => {
    let cancelled = false;
    appBuild()
      .then((build) => {
        if (!cancelled) setLabel(`SecureVault ${build.version} · ${build.commit}`);
      })
      .catch(() => {
        if (!cancelled) setLabel("SecureVault");
      });
    return () => {
      cancelled = true;
    };
  }, []);

  return <p className="build-stamp">{label}</p>;
}

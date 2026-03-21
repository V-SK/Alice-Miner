import { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/tauri";
import Sidebar from "./components/Sidebar";
import Dashboard from "./pages/Dashboard";
import Wallet from "./pages/Wallet";
import Hardware from "./pages/Hardware";
import Earnings from "./pages/Earnings";
import Logs from "./pages/Logs";
import Settings from "./pages/Settings";
import Setup from "./pages/Setup";
import { useAppStore } from "./hooks/useAppStore";

type Page = "dashboard" | "wallet" | "hardware" | "earnings" | "logs" | "settings";

function App() {
  const [currentPage, setCurrentPage] = useState<Page>("dashboard");
  const [isSetupComplete, setIsSetupComplete] = useState<boolean | null>(null);
  const { setWalletAddress, setNetworkStatus, setGpuInfo } = useAppStore();

  useEffect(() => {
    // Check if setup is complete
    const checkSetup = async () => {
      try {
        const address = await invoke<string | null>("get_wallet_address");
        if (address) {
          setWalletAddress(address);
          setIsSetupComplete(true);
        } else {
          setIsSetupComplete(false);
        }
      } catch (e) {
        console.error("Failed to check wallet:", e);
        setIsSetupComplete(false);
      }
    };

    // Initial network check
    const checkNetwork = async () => {
      try {
        const status = await invoke<any>("diagnose_network");
        setNetworkStatus(status);
      } catch (e) {
        console.error("Network check failed:", e);
      }
    };

    // Initial GPU check
    const checkGpu = async () => {
      try {
        const gpus = await invoke<any[]>("detect_gpu");
        setGpuInfo(gpus);
      } catch (e) {
        console.error("GPU check failed:", e);
      }
    };

    checkSetup();
    checkNetwork();
    checkGpu();
  }, []);

  const handleSetupComplete = (address: string) => {
    setWalletAddress(address);
    setIsSetupComplete(true);
  };

  // Loading state
  if (isSetupComplete === null) {
    return (
      <div className="h-screen bg-black flex items-center justify-center">
        <div className="text-center">
          <div className="w-16 h-16 mx-auto mb-4 border-4 border-alice-500 border-t-transparent rounded-full animate-spin" />
          <p className="text-zinc-400">Loading...</p>
        </div>
      </div>
    );
  }

  // Setup flow
  if (!isSetupComplete) {
    return <Setup onComplete={handleSetupComplete} />;
  }

  // Main app
  return (
    <div className="h-screen bg-black flex overflow-hidden">
      <Sidebar currentPage={currentPage} onPageChange={setCurrentPage} />
      <main className="flex-1 overflow-auto">
        {currentPage === "dashboard" && <Dashboard />}
        {currentPage === "wallet" && <Wallet />}
        {currentPage === "hardware" && <Hardware />}
        {currentPage === "earnings" && <Earnings />}
        {currentPage === "logs" && <Logs />}
        {currentPage === "settings" && <Settings />}
      </main>
    </div>
  );
}

export default App;

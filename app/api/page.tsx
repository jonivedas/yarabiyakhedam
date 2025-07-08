"use client"

import type React from "react"

import { useState, useEffect } from "react"
import { Shield, Home, QrCode, Upload, File, Globe, Mail, Link } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Input } from "@/components/ui/input"
import { Textarea } from "@/components/ui/textarea"
import { Card, CardContent } from "@/components/ui/card"
import QRScanner from "@/components/qr-scanner"
import ScanResults from "@/components/scan-results"

export default function HomePage() {
  const [user, setUser] = useState<any>(null)
  const [scanHistory, setScanHistory] = useState<any[]>([])
  const [isLoggedIn, setIsLoggedIn] = useState(false)
  const [showAuth, setShowAuth] = useState(false)
  const [authMode, setAuthMode] = useState<"login" | "signup">("login")
  const [scanResult, setScanResult] = useState<any | null>(null)
  const [isScanning, setIsScanning] = useState(false)
  const [showQRScanner, setShowQRScanner] = useState(false)
  const [lastScannedTarget, setLastScannedTarget] = useState<string>("")
  const [activeTab, setActiveTab] = useState<string>("qr-code")

  // Add input state management
  const [urlInput, setUrlInput] = useState("")
  const [domainInput, setDomainInput] = useState("")
  const [emailInput, setEmailInput] = useState("")

  // Check authentication status on component mount
  useEffect(() => {
    checkAuthStatus()
  }, [])

  const checkAuthStatus = async () => {
    try {
      const response = await fetch("/api/auth", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ action: "verify" }),
      })

      if (response.ok) {
        const data = await response.json()
        if (data.success) {
          setUser(data.user)
          setIsLoggedIn(true)
          loadScanHistory()
        }
      }
    } catch (error) {
      console.error("Auth check failed:", error)
    }
  }

  const loadScanHistory = async () => {
    try {
      const response = await fetch("/api/scan/history")
      if (response.ok) {
        const data = await response.json()
        setScanHistory(data.history || [])
      }
    } catch (error) {
      console.error("Failed to load scan history:", error)
    }
  }

  const handleAuthAction = async (action: string, provider: string, email?: string, password?: string) => {
    try {
      const response = await fetch("/api/auth", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ action, provider, email, password }),
      })

      const data = await response.json()

      if (data.success) {
        setUser(data.user)
        setIsLoggedIn(true)
        setShowAuth(false)
        loadScanHistory()
      } else {
        alert(data.error || "Authentication failed")
      }
    } catch (error) {
      console.error("Auth error:", error)
      alert("Authentication failed")
    }
  }

  const handleLogout = async () => {
    try {
      await fetch("/api/auth", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ action: "logout" }),
      })

      setUser(null)
      setIsLoggedIn(false)
      setScanHistory([])
    } catch (error) {
      console.error("Logout error:", error)
    }
  }

  // Helper function to detect if input is an IP address
  const isIPAddress = (input: string) => {
    const ipRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/
    return ipRegex.test(input)
  }

  const handleScan = async (type: string, data?: string) => {
    let targetData = data

    // Get data from input fields if not provided
    if (!targetData) {
      switch (type) {
        case "url":
          targetData = urlInput
          break
        case "domain":
          targetData = domainInput
          break
        case "email":
          targetData = emailInput
          break
        default:
          targetData = ""
      }
    }

    if (!targetData) {
      alert("Please enter a value to scan")
      return
    }

    // Auto-detect if domain input is actually an IP address
    if (type === "domain" && isIPAddress(targetData)) {
      type = "ip"
    }

    setIsScanning(true)
    setScanResult(null)
    setLastScannedTarget(targetData)

    try {
      console.log(`Scanning ${type}: ${targetData}`)

      const response = await fetch("/api/scan", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          scanType: type,
          target: targetData,
        }),
      })

      const result = await response.json()
      console.log("Scan result:", result)

      if (result.success) {
        setScanResult(result.result)
      } else {
        console.error("Scan failed:", result.error)
        setScanResult({ error: result.error })
      }
    } catch (error) {
      console.error("Scan error:", error)
      setScanResult({ error: "Scan failed" })
    } finally {
      setIsScanning(false)
    }
  }

  const handleFileUpload = async (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0]
    if (file) {
      const formData = new FormData()
      formData.append("file", file)

      setIsScanning(true)
      setScanResult(null)

      try {
        const response = await fetch("/api/scan/file", {
          method: "POST",
          body: formData,
        })

        const result = await response.json()

        if (result.success) {
          setScanResult(result.result)
        } else {
          setScanResult({ error: result.error })
        }
      } catch (error) {
        console.error("File scan error:", error)
        setScanResult({ error: "File scan failed" })
      } finally {
        setIsScanning(false)
      }
    }
  }

  if (showAuth) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-slate-900 via-blue-900 to-slate-900 flex items-center justify-center p-4">
        <Card className="w-full max-w-md bg-slate-800/50 border-slate-700 backdrop-blur-sm">
          <CardContent className="p-8">
            <div className="text-center mb-8">
              <h1 className="text-2xl font-bold text-purple-400 mb-4">
                {authMode === "login" ? "Welcome back" : "Create your account"}
              </h1>
              <div className="flex justify-center space-x-2 mb-6">
                <div className="w-2 h-2 rounded-full bg-purple-400"></div>
                <div className="w-2 h-2 rounded-full bg-slate-600"></div>
                <div className="w-2 h-2 rounded-full bg-slate-600"></div>
                <div className="w-2 h-2 rounded-full bg-slate-600"></div>
              </div>
            </div>

            <div className="space-y-4">
              <Button
                className="w-full bg-red-500 hover:bg-red-600 text-white py-3 rounded-lg flex items-center justify-center space-x-2"
                onClick={() => handleAuthAction(authMode, "google")}
              >
                <svg className="w-5 h-5" viewBox="0 0 24 24">
                  <path
                    fill="currentColor"
                    d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"
                  />
                  <path
                    fill="currentColor"
                    d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"
                  />
                  <path
                    fill="currentColor"
                    d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z"
                  />
                  <path
                    fill="currentColor"
                    d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"
                  />
                </svg>
                <span>Continue with Google</span>
              </Button>

              <Button
                className="w-full bg-black hover:bg-gray-900 text-white py-3 rounded-lg flex items-center justify-center space-x-2"
                onClick={() => handleAuthAction(authMode, "github")}
              >
                <svg className="w-5 h-5" fill="currentColor" viewBox="0 0 24 24">
                  <path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z" />
                </svg>
                <span>Continue with GitHub</span>
              </Button>

              <Button
                className="w-full bg-blue-600 hover:bg-blue-700 text-white py-3 rounded-lg flex items-center justify-center space-x-2"
                onClick={() => handleAuthAction(authMode, "email", "demo@example.com", "password123")}
              >
                <Mail className="w-5 h-5" />
                <span>Continue with Email</span>
              </Button>
            </div>

            {authMode === "login" && (
              <div className="mt-6 text-center">
                <button className="text-blue-400 hover:text-blue-300 text-sm">Forgot password?</button>
                <p className="text-slate-400 text-sm mt-2">
                  Don't have an account?{" "}
                  <button className="text-purple-400 hover:text-purple-300" onClick={() => setAuthMode("signup")}>
                    Create an account
                  </button>
                </p>
              </div>
            )}

            {authMode === "signup" && (
              <div className="mt-6 text-center">
                <p className="text-slate-400 text-sm">
                  Already have an account?{" "}
                  <button className="text-purple-400 hover:text-purple-300" onClick={() => setAuthMode("login")}>
                    Sign in
                  </button>
                </p>
              </div>
            )}

            <Button
              variant="ghost"
              className="w-full mt-4 text-slate-400 hover:text-white"
              onClick={() => setShowAuth(false)}
            >
              Back to Scanner
            </Button>
          </CardContent>
        </Card>
      </div>
    )
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-blue-900 to-slate-900">
      {/* Header */}
      <header className="flex items-center justify-between p-6">
        <div className="flex items-center space-x-2">
          <Shield className="w-8 h-8 text-purple-400" />
          <span className="text-xl font-bold text-white">UltimateScanner</span>
        </div>

        <div className="flex items-center space-x-4">
          <Button variant="ghost" className="text-white hover:text-purple-400">
            <Home className="w-4 h-4 mr-2" />
            Home
          </Button>

          {isLoggedIn ? (
            <Button onClick={handleLogout} className="bg-red-600 hover:bg-red-700 text-white">
              Logout
            </Button>
          ) : (
            <div className="space-x-2">
              <Button
                variant="outline"
                className="border-slate-600 text-white hover:bg-slate-800 bg-transparent"
                onClick={() => {
                  setAuthMode("login")
                  setShowAuth(true)
                }}
              >
                Login
              </Button>
              <Button
                className="bg-purple-600 hover:bg-purple-700 text-white"
                onClick={() => {
                  setAuthMode("signup")
                  setShowAuth(true)
                }}
              >
                Sign Up
              </Button>
            </div>
          )}
        </div>
      </header>

      {/* Main Content */}
      <div className="flex items-center justify-center px-6 py-12">
        <Card className="w-full max-w-4xl bg-slate-800/50 border-slate-700 backdrop-blur-sm">
          <CardContent className="p-8">
            <Tabs defaultValue="qr-code" className="w-full" onValueChange={setActiveTab}>
              <TabsList className="grid w-full grid-cols-5 bg-slate-700/50 mb-8">
                <TabsTrigger value="file" className="data-[state=active]:bg-slate-600 text-white">
                  <File className="w-4 h-4 mr-2" />
                  FILE
                </TabsTrigger>
                <TabsTrigger value="url" className="data-[state=active]:bg-slate-600 text-white">
                  <Link className="w-4 h-4 mr-2" />
                  URL
                </TabsTrigger>
                <TabsTrigger value="domain" className="data-[state=active]:bg-slate-600 text-white">
                  <Globe className="w-4 h-4 mr-2" />
                  DOMAIN
                </TabsTrigger>
                <TabsTrigger value="qr-code" className="data-[state=active]:bg-slate-600 text-white">
                  <QrCode className="w-4 h-4 mr-2" />
                  QR CODE
                </TabsTrigger>
                <TabsTrigger value="email" className="data-[state=active]:bg-slate-600 text-white">
                  <Mail className="w-4 h-4 mr-2" />
                  EMAIL
                </TabsTrigger>
              </TabsList>

              <TabsContent value="file" className="space-y-6">
                <div className="text-center">
                  <input
                    type="file"
                    id="file-upload"
                    className="hidden"
                    onChange={handleFileUpload}
                    accept=".exe,.pdf,.doc,.docx,.zip,.rar"
                  />
                  <label
                    htmlFor="file-upload"
                    className="inline-flex items-center justify-center w-full max-w-md h-32 border-2 border-dashed border-slate-600 rounded-lg cursor-pointer hover:border-blue-500 transition-colors"
                  >
                    <div className="text-center">
                      <Upload className="w-8 h-8 text-slate-400 mx-auto mb-2" />
                      <p className="text-slate-300">Click to upload file</p>
                      <p className="text-slate-500 text-sm">Max size: 32MB</p>
                    </div>
                  </label>
                </div>
              </TabsContent>

              <TabsContent value="url" className="space-y-6">
                <div className="space-y-4">
                  <Input
                    value={urlInput}
                    onChange={(e) => setUrlInput(e.target.value)}
                    placeholder="Enter URL to scan (e.g., https://mozilla.org)"
                    className="bg-slate-700 border-slate-600 text-white placeholder-slate-400"
                  />
                  <Button
                    className="w-full bg-blue-600 hover:bg-blue-700"
                    onClick={() => handleScan("url")}
                    disabled={isScanning}
                  >
                    {isScanning ? "Scanning..." : "Scan URL"}
                  </Button>
                </div>
              </TabsContent>

              <TabsContent value="domain" className="space-y-6">
                <div className="space-y-4">
                  <Input
                    value={domainInput}
                    onChange={(e) => setDomainInput(e.target.value)}
                    placeholder="Enter domain or IP (e.g., mozilla.org or 8.8.8.8)"
                    className="bg-slate-700 border-slate-600 text-white placeholder-slate-400"
                  />
                  <Button
                    className="w-full bg-blue-600 hover:bg-blue-700"
                    onClick={() => handleScan("domain")}
                    disabled={isScanning}
                  >
                    {isScanning ? "Scanning..." : "Scan Domain/IP"}
                  </Button>
                  <p className="text-sm text-slate-400 text-center">Automatically detects domains and IP addresses</p>
                </div>
              </TabsContent>

              <TabsContent value="qr-code" className="space-y-6">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                  <Button
                    className="h-32 bg-blue-600 hover:bg-blue-700 text-white flex flex-col items-center justify-center space-y-2"
                    onClick={() => setShowQRScanner(true)}
                  >
                    <QrCode className="w-8 h-8" />
                    <span className="font-medium">Scan with Camera</span>
                  </Button>

                  <div className="relative">
                    <input type="file" id="qr-upload" className="hidden" onChange={handleFileUpload} accept="image/*" />
                    <label
                      htmlFor="qr-upload"
                      className="flex h-32 w-full items-center justify-center border-2 border-dashed border-slate-600 rounded-lg cursor-pointer hover:border-blue-500 transition-colors"
                    >
                      <div className="text-center">
                        <Upload className="w-8 h-8 text-slate-400 mx-auto mb-2" />
                        <span className="text-slate-300 font-medium">Upload QR Image</span>
                      </div>
                    </label>
                  </div>
                </div>

                {showQRScanner && (
                  <QRScanner onScan={(data) => handleScan("qr-camera", data)} onClose={() => setShowQRScanner(false)} />
                )}
              </TabsContent>

              <TabsContent value="email" className="space-y-6">
                <div className="space-y-4">
                  <Input
                    value={emailInput}
                    onChange={(e) => setEmailInput(e.target.value)}
                    placeholder="Enter email address to scan"
                    className="bg-slate-700 border-slate-600 text-white placeholder-slate-400"
                  />
                  <Textarea
                    placeholder="Paste email content or headers (optional)"
                    className="bg-slate-700 border-slate-600 text-white placeholder-slate-400 min-h-[100px]"
                  />
                  <Button
                    className="w-full bg-blue-600 hover:bg-blue-700"
                    onClick={() => handleScan("email")}
                    disabled={isScanning}
                  >
                    {isScanning ? "Scanning..." : "Scan Email"}
                  </Button>
                </div>
              </TabsContent>
            </Tabs>

            {/* Loading State */}
            {isScanning && (
              <div className="mt-8 text-center">
                <div className="inline-flex items-center space-x-2">
                  <div className="animate-spin rounded-full h-6 w-6 border-b-2 border-blue-500"></div>
                  <span className="text-white">Scanning with VirusTotal...</span>
                </div>
              </div>
            )}

            {/* Scan Results */}
            {scanResult && (
              <ScanResults
                result={scanResult}
                scanType={activeTab || "url"}
                target={lastScannedTarget || ""}
                onRescan={() => handleScan(activeTab || "url", lastScannedTarget || "")}
              />
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  )
}

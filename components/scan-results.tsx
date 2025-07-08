"use client"

import { useState } from "react"
import { Card, CardContent } from "@/components/ui/card"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import {
  ExternalLink,
  Shield,
  AlertTriangle,
  CheckCircle,
  XCircle,
  Clock,
  RefreshCw,
  Globe,
  Server,
} from "lucide-react"

interface ScanResultsProps {
  result: any
  scanType: string
  target: string
  onRescan?: () => void
}

export default function ScanResults({ result, scanType, target, onRescan }: ScanResultsProps) {
  const [activeTab, setActiveTab] = useState("detection")

  if (!result) return null

  const { positives = 0, total = 0, scans = {}, scan_date, permalink, verbose_msg, domain_info, ip_info } = result

  // Calculate threat level
  const threatLevel = positives === 0 ? "clean" : positives <= 3 ? "suspicious" : "malicious"
  const threatColors = {
    clean: {
      border: "border-green-500",
      bg: "bg-green-500/10",
      text: "text-green-400",
      stroke: "stroke-green-500",
    },
    suspicious: {
      border: "border-yellow-500",
      bg: "bg-yellow-500/10",
      text: "text-yellow-400",
      stroke: "stroke-yellow-500",
    },
    malicious: {
      border: "border-red-500",
      bg: "bg-red-500/10",
      text: "text-red-400",
      stroke: "stroke-red-500",
    },
  }

  const colors = threatColors[threatLevel]

  // Convert scans object to array for display
  const scanResults = Object.entries(scans).map(([vendor, data]: [string, any]) => ({
    vendor,
    detected: data.detected || false,
    result: data.result || "Clean",
    update: data.update || "Unknown",
    version: data.version || "Unknown",
  }))

  const detectedCount = scanResults.filter((scan) => scan.detected).length
  const cleanCount = scanResults.filter((scan) => !scan.detected).length

  return (
    <div className="mt-8 space-y-6">
      {/* Summary Card */}
      <Card className={`border-2 ${colors.border} ${colors.bg}`}>
        <CardContent className="p-6">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-4">
              {/* Circular Progress Indicator */}
              <div className="relative w-20 h-20">
                <svg className="w-20 h-20 transform -rotate-90" viewBox="0 0 36 36">
                  <path
                    className="text-slate-600"
                    stroke="currentColor"
                    strokeWidth="3"
                    fill="none"
                    d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
                  />
                  <path
                    className={colors.text}
                    stroke="currentColor"
                    strokeWidth="3"
                    strokeDasharray={`${total > 0 ? (positives / total) * 100 : 0}, 100`}
                    strokeLinecap="round"
                    fill="none"
                    d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
                  />
                </svg>
                <div className="absolute inset-0 flex items-center justify-center">
                  <div className="text-center">
                    <div className={`text-lg font-bold ${colors.text}`}>{positives}</div>
                    <div className="text-xs text-slate-400">/{total}</div>
                  </div>
                </div>
              </div>

              <div>
                <div className="flex items-center space-x-2 mb-2">
                  {positives > 0 ? (
                    <AlertTriangle className={`w-5 h-5 ${colors.text}`} />
                  ) : (
                    <CheckCircle className="w-5 h-5 text-green-400" />
                  )}
                  <span className={`text-lg font-semibold ${colors.text}`}>
                    {positives > 0
                      ? `${positives} security vendor${positives > 1 ? "s" : ""} flagged this ${scanType} as malicious`
                      : `No security vendors flagged this ${scanType} as malicious`}
                  </span>
                </div>
                <div className="text-slate-300 break-all">{target}</div>
                {verbose_msg && <div className="text-sm text-slate-400 mt-1">{verbose_msg}</div>}
              </div>
            </div>

            <div className="text-right space-y-2">
              <div className="text-sm text-slate-400">
                <div>
                  Status: <span className="text-white">200</span>
                </div>
                <div>
                  Content type: <span className="text-white">text/html; charset=UTF-8</span>
                </div>
                <div>
                  Last Analysis Date: <span className="text-white">{new Date(scan_date).toLocaleString()}</span>
                </div>
              </div>
              <div className="flex space-x-2">
                {onRescan && (
                  <Button
                    size="sm"
                    variant="outline"
                    onClick={onRescan}
                    className="text-white border-slate-600 bg-transparent"
                  >
                    <RefreshCw className="w-4 h-4 mr-1" />
                    Reanalyze
                  </Button>
                )}
                {permalink && (
                  <Button size="sm" variant="outline" asChild className="text-white border-slate-600 bg-transparent">
                    <a href={permalink} target="_blank" rel="noopener noreferrer">
                      <ExternalLink className="w-4 h-4 mr-1" />
                      View on VirusTotal
                    </a>
                  </Button>
                )}
              </div>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Detailed Results Tabs */}
      <Card className="bg-slate-800/50 border-slate-700">
        <CardContent className="p-0">
          <Tabs value={activeTab} onValueChange={setActiveTab}>
            <TabsList className="w-full bg-slate-700/50 rounded-none border-b border-slate-600">
              <TabsTrigger value="detection" className="data-[state=active]:bg-slate-600 text-white">
                DETECTION
              </TabsTrigger>
              <TabsTrigger value="details" className="data-[state=active]:bg-slate-600 text-white">
                DETAILS
              </TabsTrigger>
              <TabsTrigger value="community" className="data-[state=active]:bg-slate-600 text-white">
                COMMUNITY
              </TabsTrigger>
            </TabsList>

            <TabsContent value="detection" className="p-6">
              <div className="space-y-4">
                <div className="flex items-center justify-between">
                  <h3 className="text-lg font-semibold text-white flex items-center">
                    <Shield className="w-5 h-5 mr-2" />
                    Security vendors' analysis
                  </h3>
                  <div className="text-sm text-slate-400">Do you want to automate checks?</div>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  {scanResults.map((scan, index) => (
                    <div
                      key={index}
                      className="flex items-center justify-between p-3 bg-slate-700/30 rounded-lg border border-slate-600"
                    >
                      <div className="flex items-center space-x-3">
                        <span className="text-white font-medium">{scan.vendor}</span>
                      </div>
                      <div className="flex items-center space-x-2">
                        {scan.detected ? (
                          <>
                            <XCircle className="w-4 h-4 text-red-400" />
                            <Badge variant="destructive" className="bg-red-500/20 text-red-400 border-red-500/30">
                              {scan.result}
                            </Badge>
                          </>
                        ) : (
                          <>
                            <CheckCircle className="w-4 h-4 text-green-400" />
                            <Badge variant="secondary" className="bg-green-500/20 text-green-400 border-green-500/30">
                              Clean
                            </Badge>
                          </>
                        )}
                      </div>
                    </div>
                  ))}
                </div>

                {scanResults.length === 0 && (
                  <div className="text-center py-8 text-slate-400">
                    <Clock className="w-8 h-8 mx-auto mb-2" />
                    <p>Scan results are being processed. Please wait...</p>
                  </div>
                )}
              </div>
            </TabsContent>

            <TabsContent value="details" className="p-6">
              <div className="space-y-6">
                <h3 className="text-lg font-semibold text-white">Scan Details</h3>

                {/* Basic Details */}
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div className="space-y-2">
                    <div className="text-sm text-slate-400">Resource</div>
                    <div className="text-white break-all">{result.resource || target}</div>
                  </div>
                  <div className="space-y-2">
                    <div className="text-sm text-slate-400">Scan Date</div>
                    <div className="text-white">{new Date(scan_date).toLocaleString()}</div>
                  </div>
                  <div className="space-y-2">
                    <div className="text-sm text-slate-400">Detections</div>
                    <div className="text-white">
                      {positives} / {total}
                    </div>
                  </div>
                  <div className="space-y-2">
                    <div className="text-sm text-slate-400">Scan Type</div>
                    <div className="text-white capitalize">{scanType}</div>
                  </div>
                </div>

                {/* Domain-specific information */}
                {domain_info && (
                  <div className="space-y-4">
                    <h4 className="text-md font-semibold text-white flex items-center">
                      <Globe className="w-4 h-4 mr-2" />
                      Domain Information
                    </h4>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                      <div className="space-y-2">
                        <div className="text-sm text-slate-400">Detected URLs</div>
                        <div className="text-white">{domain_info.detected_urls?.length || 0}</div>
                      </div>
                      <div className="space-y-2">
                        <div className="text-sm text-slate-400">Communicating Samples</div>
                        <div className="text-white">{domain_info.detected_communicating_samples?.length || 0}</div>
                      </div>
                      <div className="space-y-2">
                        <div className="text-sm text-slate-400">Downloaded Samples</div>
                        <div className="text-white">{domain_info.detected_downloaded_samples?.length || 0}</div>
                      </div>
                      <div className="space-y-2">
                        <div className="text-sm text-slate-400">Categories</div>
                        <div className="text-white">{domain_info.categories?.join(", ") || "None"}</div>
                      </div>
                    </div>
                  </div>
                )}

                {/* IP-specific information */}
                {ip_info && (
                  <div className="space-y-4">
                    <h4 className="text-md font-semibold text-white flex items-center">
                      <Server className="w-4 h-4 mr-2" />
                      IP Address Information
                    </h4>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                      <div className="space-y-2">
                        <div className="text-sm text-slate-400">Country</div>
                        <div className="text-white">{ip_info.country}</div>
                      </div>
                      <div className="space-y-2">
                        <div className="text-sm text-slate-400">AS Owner</div>
                        <div className="text-white">{ip_info.as_owner}</div>
                      </div>
                      <div className="space-y-2">
                        <div className="text-sm text-slate-400">ASN</div>
                        <div className="text-white">{ip_info.asn}</div>
                      </div>
                      <div className="space-y-2">
                        <div className="text-sm text-slate-400">Detected URLs</div>
                        <div className="text-white">{ip_info.detected_urls?.length || 0}</div>
                      </div>
                    </div>
                  </div>
                )}

                {/* File hashes if available */}
                {result.md5 && (
                  <div className="space-y-2">
                    <div className="text-sm text-slate-400">MD5</div>
                    <div className="text-white font-mono text-sm">{result.md5}</div>
                  </div>
                )}
                {result.sha1 && (
                  <div className="space-y-2">
                    <div className="text-sm text-slate-400">SHA1</div>
                    <div className="text-white font-mono text-sm">{result.sha1}</div>
                  </div>
                )}
                {result.sha256 && (
                  <div className="space-y-2">
                    <div className="text-sm text-slate-400">SHA256</div>
                    <div className="text-white font-mono text-sm">{result.sha256}</div>
                  </div>
                )}
              </div>
            </TabsContent>

            <TabsContent value="community" className="p-6">
              <div className="space-y-4">
                <h3 className="text-lg font-semibold text-white">Community</h3>
                <div className="text-center py-8 text-slate-400">
                  <p>Community comments and votes will be displayed here.</p>
                  <p className="text-sm mt-2">This feature requires additional VirusTotal API endpoints.</p>
                </div>
              </div>
            </TabsContent>
          </Tabs>
        </CardContent>
      </Card>
    </div>
  )
}

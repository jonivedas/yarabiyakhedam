import { type NextRequest, NextResponse } from "next/server"
import crypto from "crypto"

const VIRUSTOTAL_API_KEY = "047673d4aa55dfb43497a72b4f70d126fc38b9bac2a4abaeace83275ea370699"

export async function POST(request: NextRequest) {
  try {
    const formData = await request.formData()
    const file = formData.get("file") as File

    if (!file) {
      return NextResponse.json({ success: false, error: "No file provided" }, { status: 400 })
    }

    // Check file size (VirusTotal has a 32MB limit for public API)
    if (file.size > 32 * 1024 * 1024) {
      return NextResponse.json(
        {
          success: false,
          error: "File too large. Maximum size is 32MB",
        },
        { status: 400 },
      )
    }

    // Convert file to buffer and calculate hash
    const arrayBuffer = await file.arrayBuffer()
    const buffer = Buffer.from(arrayBuffer)
    const hash = crypto.createHash("sha256").update(buffer).digest("hex")

    // First, check if file hash exists in VirusTotal database
    const reportParams = new URLSearchParams()
    reportParams.append("apikey", VIRUSTOTAL_API_KEY)
    reportParams.append("resource", hash)

    const reportResponse = await fetch(`https://www.virustotal.com/vtapi/v2/file/report?${reportParams.toString()}`)
    const reportData = await reportResponse.json()

    if (reportData.response_code === 1) {
      // File already scanned, return existing results
      return NextResponse.json({
        success: true,
        result: {
          response_code: reportData.response_code,
          filename: file.name,
          resource: hash,
          positives: reportData.positives,
          total: reportData.total,
          scan_date: reportData.scan_date,
          permalink: reportData.permalink,
          scans: reportData.scans || {},
          verbose_msg: reportData.verbose_msg,
          md5: reportData.md5,
          sha1: reportData.sha1,
          sha256: reportData.sha256,
        },
        timestamp: new Date().toISOString(),
      })
    }

    // File not in database, submit for scanning
    const scanFormData = new FormData()
    scanFormData.append("apikey", VIRUSTOTAL_API_KEY)
    scanFormData.append("file", file)

    const scanResponse = await fetch("https://www.virustotal.com/vtapi/v2/file/scan", {
      method: "POST",
      body: scanFormData,
    })

    const scanData = await scanResponse.json()

    if (scanData.response_code === 1) {
      // Wait for scan to complete
      await new Promise((resolve) => setTimeout(resolve, 5000))

      // Try to get results
      const finalReportResponse = await fetch(
        `https://www.virustotal.com/vtapi/v2/file/report?${reportParams.toString()}`,
      )
      const finalReportData = await finalReportResponse.json()

      return NextResponse.json({
        success: true,
        result: {
          response_code: finalReportData.response_code || 0,
          filename: file.name,
          resource: hash,
          positives: finalReportData.positives || 0,
          total: finalReportData.total || 0,
          scan_date: finalReportData.scan_date || new Date().toISOString(),
          permalink: finalReportData.permalink || scanData.permalink,
          scans: finalReportData.scans || {},
          scan_id: scanData.scan_id,
          verbose_msg: finalReportData.verbose_msg || "File submitted for scanning",
          md5: finalReportData.md5,
          sha1: finalReportData.sha1,
          sha256: hash,
        },
        timestamp: new Date().toISOString(),
      })
    } else {
      throw new Error("Failed to submit file for scanning")
    }
  } catch (error) {
    console.error("File scan error:", error)
    return NextResponse.json(
      {
        success: false,
        error: "Failed to scan file with VirusTotal API",
        details: error instanceof Error ? error.message : "Unknown error",
      },
      { status: 500 },
    )
  }
}

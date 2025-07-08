import { type NextRequest, NextResponse } from "next/server"
import { cookies } from "next/headers"

// Simple in-memory storage for scan history (use database in production)
const scanHistory = new Map()
const sessions = new Map()

export async function GET(request: NextRequest) {
  try {
    const token = cookies().get("auth-token")?.value

    if (!token || !sessions.has(token)) {
      return NextResponse.json({ success: false, error: "Not authenticated" }, { status: 401 })
    }

    const session = sessions.get(token)
    const userHistory = scanHistory.get(session.email) || []

    return NextResponse.json({
      success: true,
      history: userHistory,
    })
  } catch (error) {
    console.error("History fetch error:", error)
    return NextResponse.json(
      {
        success: false,
        error: "Failed to fetch scan history",
      },
      { status: 500 },
    )
  }
}

export async function POST(request: NextRequest) {
  try {
    const token = cookies().get("auth-token")?.value

    if (!token || !sessions.has(token)) {
      return NextResponse.json({ success: false, error: "Not authenticated" }, { status: 401 })
    }

    const session = sessions.get(token)
    const { scanType, target, result } = await request.json()

    const historyEntry = {
      id: Date.now().toString(),
      scanType,
      target,
      result,
      timestamp: new Date().toISOString(),
    }

    if (!scanHistory.has(session.email)) {
      scanHistory.set(session.email, [])
    }

    const userHistory = scanHistory.get(session.email)
    userHistory.unshift(historyEntry) // Add to beginning of array

    // Keep only last 100 scans
    if (userHistory.length > 100) {
      userHistory.splice(100)
    }

    return NextResponse.json({
      success: true,
      entry: historyEntry,
    })
  } catch (error) {
    console.error("History save error:", error)
    return NextResponse.json(
      {
        success: false,
        error: "Failed to save scan history",
      },
      { status: 500 },
    )
  }
}

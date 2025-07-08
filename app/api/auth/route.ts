import { type NextRequest, NextResponse } from "next/server"
import { cookies } from "next/headers"
import crypto from "crypto"

// Simple in-memory user store (in production, use a proper database)
const users = new Map()
const sessions = new Map()

function hashPassword(password: string): string {
  return crypto.createHash("sha256").update(password).digest("hex")
}

function generateToken(): string {
  return crypto.randomBytes(32).toString("hex")
}

export async function POST(request: NextRequest) {
  try {
    const { action, provider, email, password } = await request.json()

    if (action === "signup") {
      if (!email) {
        return NextResponse.json({ success: false, error: "Email is required" }, { status: 400 })
      }

      if (users.has(email)) {
        return NextResponse.json({ success: false, error: "User already exists" }, { status: 400 })
      }

      const user = {
        email,
        provider: provider || "email",
        passwordHash: password ? hashPassword(password) : null,
        createdAt: new Date().toISOString(),
      }

      users.set(email, user)

      const token = generateToken()
      sessions.set(token, { email, createdAt: Date.now() })

      cookies().set("auth-token", token, {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: "strict",
        maxAge: 60 * 60 * 24 * 7, // 7 days
      })

      return NextResponse.json({
        success: true,
        user: {
          email: user.email,
          provider: user.provider,
        },
      })
    }

    if (action === "login") {
      if (provider !== "email") {
        // OAuth login simulation - in production, verify with OAuth provider
        const user = {
          email: email || `user@${provider}.com`,
          provider,
          createdAt: new Date().toISOString(),
        }

        if (!users.has(user.email)) {
          users.set(user.email, user)
        }

        const token = generateToken()
        sessions.set(token, { email: user.email, createdAt: Date.now() })

        cookies().set("auth-token", token, {
          httpOnly: true,
          secure: process.env.NODE_ENV === "production",
          sameSite: "strict",
          maxAge: 60 * 60 * 24 * 7,
        })

        return NextResponse.json({
          success: true,
          user: {
            email: user.email,
            provider: user.provider,
          },
        })
      }

      // Email/password login
      if (!email || !password) {
        return NextResponse.json({ success: false, error: "Email and password are required" }, { status: 400 })
      }

      const user = users.get(email)
      if (!user) {
        return NextResponse.json({ success: false, error: "User not found" }, { status: 404 })
      }

      if (user.passwordHash !== hashPassword(password)) {
        return NextResponse.json({ success: false, error: "Invalid password" }, { status: 401 })
      }

      const token = generateToken()
      sessions.set(token, { email, createdAt: Date.now() })

      cookies().set("auth-token", token, {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: "strict",
        maxAge: 60 * 60 * 24 * 7,
      })

      return NextResponse.json({
        success: true,
        user: {
          email: user.email,
          provider: user.provider,
        },
      })
    }

    if (action === "logout") {
      const token = cookies().get("auth-token")?.value
      if (token) {
        sessions.delete(token)
        cookies().delete("auth-token")
      }
      return NextResponse.json({ success: true })
    }

    if (action === "verify") {
      const token = cookies().get("auth-token")?.value
      if (!token || !sessions.has(token)) {
        return NextResponse.json({ success: false, error: "Not authenticated" }, { status: 401 })
      }

      const session = sessions.get(token)
      const user = users.get(session.email)

      return NextResponse.json({
        success: true,
        user: {
          email: user.email,
          provider: user.provider,
        },
      })
    }

    return NextResponse.json({ success: false, error: "Invalid action" }, { status: 400 })
  } catch (error) {
    console.error("Auth error:", error)
    return NextResponse.json({ success: false, error: "Authentication failed" }, { status: 500 })
  }
}

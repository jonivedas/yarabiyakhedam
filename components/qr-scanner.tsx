"use client"

import { useEffect, useRef, useState } from "react"
import { Button } from "@/components/ui/button"
import { X } from "lucide-react"

interface QRScannerProps {
  onScan: (data: string) => void
  onClose: () => void
}

export default function QRScanner({ onScan, onClose }: QRScannerProps) {
  const videoRef = useRef<HTMLVideoElement>(null)
  const canvasRef = useRef<HTMLCanvasElement>(null)
  const [isScanning, setIsScanning] = useState(false)
  const [stream, setStream] = useState<MediaStream | null>(null)

  useEffect(() => {
    startCamera()
    return () => {
      stopCamera()
    }
  }, [])

  const startCamera = async () => {
    try {
      const mediaStream = await navigator.mediaDevices.getUserMedia({
        video: { facingMode: "environment" },
      })

      setStream(mediaStream)

      if (videoRef.current) {
        videoRef.current.srcObject = mediaStream
        videoRef.current.play()
      }

      setIsScanning(true)
      scanForQR()
    } catch (error) {
      console.error("Error accessing camera:", error)
      alert("Unable to access camera. Please check permissions.")
    }
  }

  const stopCamera = () => {
    if (stream) {
      stream.getTracks().forEach((track) => track.stop())
      setStream(null)
    }
    setIsScanning(false)
  }

  const scanForQR = () => {
    if (!isScanning || !videoRef.current || !canvasRef.current) return

    const video = videoRef.current
    const canvas = canvasRef.current
    const context = canvas.getContext("2d")

    if (context && video.readyState === video.HAVE_ENOUGH_DATA) {
      canvas.width = video.videoWidth
      canvas.height = video.videoHeight
      context.drawImage(video, 0, 0, canvas.width, canvas.height)

      // In a real implementation, you would use a QR code library like jsQR
      // For demo purposes, we'll simulate QR detection
      const imageData = context.getImageData(0, 0, canvas.width, canvas.height)

      // Simulate QR code detection (replace with actual QR library)
      setTimeout(() => {
        if (Math.random() > 0.95) {
          // 5% chance to "detect" QR code
          const mockQRData = "https://example.com/malicious-site"
          onScan(mockQRData)
          stopCamera()
          onClose()
        }
      }, 100)
    }

    if (isScanning) {
      requestAnimationFrame(scanForQR)
    }
  }

  return (
    <div className="fixed inset-0 bg-black bg-opacity-75 flex items-center justify-center z-50">
      <div className="bg-slate-800 rounded-lg p-6 max-w-md w-full mx-4">
        <div className="flex justify-between items-center mb-4">
          <h3 className="text-lg font-semibold text-white">QR Code Scanner</h3>
          <Button
            variant="ghost"
            size="sm"
            onClick={() => {
              stopCamera()
              onClose()
            }}
            className="text-white hover:text-red-400"
          >
            <X className="w-5 h-5" />
          </Button>
        </div>

        <div className="relative">
          <video ref={videoRef} className="w-full h-64 bg-black rounded-lg object-cover" playsInline muted />
          <canvas ref={canvasRef} className="hidden" />

          {/* Scanning overlay */}
          <div className="absolute inset-0 border-2 border-blue-500 rounded-lg">
            <div className="absolute top-4 left-4 w-6 h-6 border-t-2 border-l-2 border-blue-500"></div>
            <div className="absolute top-4 right-4 w-6 h-6 border-t-2 border-r-2 border-blue-500"></div>
            <div className="absolute bottom-4 left-4 w-6 h-6 border-b-2 border-l-2 border-blue-500"></div>
            <div className="absolute bottom-4 right-4 w-6 h-6 border-b-2 border-r-2 border-blue-500"></div>
          </div>
        </div>

        <p className="text-center text-slate-300 mt-4">Position QR code within the frame to scan</p>
      </div>
    </div>
  )
}

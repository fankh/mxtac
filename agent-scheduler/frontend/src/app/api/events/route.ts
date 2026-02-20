import { NextRequest } from "next/server";

const API_HOST = process.env.API_HOST ?? "localhost";

export async function GET(request: NextRequest) {
  const token = request.nextUrl.searchParams.get("token") ?? "";
  const backendUrl = `http://${API_HOST}:13002/api/events?token=${encodeURIComponent(token)}`;

  const upstream = await fetch(backendUrl, {
    headers: { Accept: "text/event-stream" },
    signal: request.signal,
  });

  if (!upstream.ok || !upstream.body) {
    return new Response("SSE upstream error", { status: 502 });
  }

  return new Response(upstream.body, {
    headers: {
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-cache, no-transform",
      Connection: "keep-alive",
    },
  });
}

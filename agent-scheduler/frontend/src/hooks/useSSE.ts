"use client";

import { useEffect, useRef, useState } from "react";

type SSEHandler = (event: string, data: unknown) => void;

export function useSSE(onEvent: SSEHandler) {
  const eventSourceRef = useRef<EventSource | null>(null);
  const handlerRef = useRef(onEvent);
  const [connected, setConnected] = useState(false);

  // Keep handler ref up to date without re-running the effect
  handlerRef.current = onEvent;

  useEffect(() => {
    const token = typeof window !== "undefined" ? localStorage.getItem("auth_token") : null;
    const url = token ? `/api/events?token=${encodeURIComponent(token)}` : "/api/events";
    const es = new EventSource(url);
    eventSourceRef.current = es;

    es.addEventListener("connected", () => setConnected(true));
    es.addEventListener("task_update", (e) => {
      try {
        handlerRef.current("task_update", JSON.parse(e.data));
      } catch {}
    });
    es.addEventListener("run_update", (e) => {
      try {
        handlerRef.current("run_update", JSON.parse(e.data));
      } catch {}
    });
    es.addEventListener("log", (e) => {
      try {
        handlerRef.current("log", JSON.parse(e.data));
      } catch {}
    });
    es.addEventListener("scheduler", (e) => {
      try {
        handlerRef.current("scheduler", JSON.parse(e.data));
      } catch {}
    });

    es.onerror = () => {
      setConnected(false);
    };

    return () => {
      es.close();
      eventSourceRef.current = null;
      setConnected(false);
    };
  }, []);

  return { connected };
}

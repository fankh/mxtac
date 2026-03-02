import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  basePath: process.env.BASE_PATH || "",
  async rewrites() {
    return [
      {
        source: "/api/:path*",
        destination: `http://${process.env.API_HOST ?? "localhost"}:${process.env.API_PORT ?? "13002"}/api/:path*`,
      },
    ];
  },
};

export default nextConfig;

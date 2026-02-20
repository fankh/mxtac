import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  async rewrites() {
    return [
      {
        source: "/api/:path*",
        destination: `http://${process.env.API_HOST ?? "localhost"}:13002/api/:path*`,
      },
    ];
  },
};

export default nextConfig;

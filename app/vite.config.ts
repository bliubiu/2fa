import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// 开发服务器固定端口，供 Tauri 的 devUrl 指向；clearScreen 关闭以免冲掉 Tauri 的 stderr 日志
export default defineConfig({
  plugins: [react()],
  clearScreen: false,
  server: {
    port: 5173,
    strictPort: true,
  },
});

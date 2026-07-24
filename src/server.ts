import { buildApp } from "./app.js";
import { createConfig } from "./config.js";

const config = createConfig();
const app = await buildApp(config);
await app.listen({ host: "127.0.0.1", port: config.listenPort });

import { createFileRoute } from "@tanstack/react-router";
import BridgeGuardApp from "@/components/bridgeguard-app";

export const Route = createFileRoute("/")({
  component: BridgeGuardApp,
});

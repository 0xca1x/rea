import type { McpServer } from "@modelcontextprotocol/server";

import { inspectDyldSharedCacheEvidence } from "../../application/apple/DyldSharedCacheService.js";
import { applicationToolContract } from "../../contracts/applicationToolContracts.js";
import { logToolExecution } from "../toolLogging.js";
import { toolRegistrationOptions } from "../toolRegistrationOptions.js";
import { toCallToolResult } from "../toolResult.js";
import { recordResult } from "./helpers.js";
import type { ApplicationToolRegistration } from "./types.js";

/** Register the target-free dyld shared cache inspection tool. */
export const registerInspectDyldSharedCacheTool = (
  server: McpServer,
  options: ApplicationToolRegistration,
): void => {
  const contract = applicationToolContract("inspect_dyld_shared_cache");
  server.registerTool(
    contract.name,
    toolRegistrationOptions(contract),
    async (input: unknown, context) => {
      const result = await logToolExecution(options.logger, contract.name, () =>
        inspectDyldSharedCacheEvidence(input, context.mcpReq.signal),
      );
      if (!result.ok) return toCallToolResult(result, contract);
      return recordResult(options, contract, result.value);
    },
  );
};

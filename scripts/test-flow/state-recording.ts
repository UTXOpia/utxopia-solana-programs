import * as fs from "fs";
import * as path from "path";

export interface FlowStateRecord {
  name: string;
  cluster: string;
  recordedAt: string;
  data: Record<string, unknown>;
}

export function writeFlowState(record: Omit<FlowStateRecord, "recordedAt">, filePath = ".last-test-flow.json"): void {
  const output: FlowStateRecord = {
    ...record,
    recordedAt: new Date().toISOString(),
  };
  fs.mkdirSync(path.dirname(path.resolve(filePath)), { recursive: true });
  fs.writeFileSync(filePath, `${JSON.stringify(output, null, 2)}\n`);
}

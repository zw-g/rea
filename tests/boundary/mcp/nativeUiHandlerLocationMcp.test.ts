import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";

import { expect } from "vitest";
import { z } from "zod";

import { AnalysisProviderRegistry } from "../../../src/application/binary/AnalysisProviderRegistry.js";
import { composeBinarySession } from "../../../src/application/binary/BinarySessionComposition.js";
import { encodeNibArchiveFixture } from "../../../src/artifacts/apple/NibArchive.fixture.js";
import { ArtifactProvider } from "../../../src/artifacts/ArtifactProvider.js";
import { nativeInvestigationTraceSchema } from "../../../src/domain/native/nativeInvestigationGraph.js";
import { NativeMacOSProvider } from "../../../src/native/NativeMacOSProvider.js";
import { createServer } from "../../../src/server/createServer.js";
import { NativeFixtureRunner } from "../../fixtures/nativeCommands.js";
import { objcRecordBudgetMacho } from "../../fixtures/objcRecordBudgetMacho.js";
import { createTestTempDirectory } from "../../fixtures/temporaryDirectory.js";
import { CPU_ARM64, universalMacho } from "../../fixtures/universalMacho.js";
import { mcpTest } from "../../support/mcp/mcpFixture.js";

// objcRecordBudgetMacho encodes FixtureClass's method_t at 0x508 and its
// implementation at 0x700, both relative to the selected Mach-O image.
const selector = "classMethod";
const methodEntryAddress = "0x100000508";
const methodEntrySliceOffset = 0x508;
const implementationAddress = "0x100000700";
const thin = objcRecordBudgetMacho("class", [0x700]);
const universal = universalMacho([
  { bytes: thin, cpuType: CPU_ARM64, cpuSubtype: 0 },
]);
const executables = [
  { container: "thin", bytes: thin, sliceOffset: 0 },
  ...universal.slices.map(({ offset }) => ({
    container: "FAT",
    bytes: universal.bytes,
    sliceOffset: offset,
  })),
];

const writeApp = async (root: string, executable: Buffer): Promise<string> => {
  const contents = join(root, "Fixture.app", "Contents");
  await mkdir(join(contents, "MacOS"), { recursive: true });
  await mkdir(join(contents, "Resources"));
  await writeFile(join(contents, "MacOS", "Fixture"), executable);
  await writeFile(
    join(contents, "Info.plist"),
    "<plist><dict><key>CFBundleExecutable</key><string>Fixture</string></dict></plist>",
  );
  // An NSNibControlConnector sends the button's action to an NSCustomObject
  // whose NSClassName is the fixture's Objective-C class.
  await writeFile(
    join(contents, "Resources", "Main.nib"),
    encodeNibArchiveFixture({
      classes: [
        "NSCustomObject",
        "NSString",
        "NSButton",
        "NSNibControlConnector",
      ],
      objects: [
        { classIndex: 0, values: { NSClassName: { ref: 1 } } },
        { classIndex: 1, values: { "NS.bytes": "FixtureClass" } },
        { classIndex: 2, values: {} },
        {
          classIndex: 3,
          values: {
            NSSource: { ref: 2 },
            NSDestination: { ref: 0 },
            NSLabel: { ref: 4 },
          },
        },
        { classIndex: 1, values: { "NS.bytes": selector } },
      ],
    }),
  );
  return join(root, "Fixture.app");
};

mcpTest.for(executables)(
  "keeps a $container handler file offset unknown while its method record stays in Evidence",
  async ({ bytes, sliceOffset }, { mcp, onTestFinished }) => {
    const app = await writeApp(
      await createTestTempDirectory("rea-native-ui-handler-"),
      bytes,
    );
    // The real Interface Builder decoder and Apple metadata byte reader, with
    // Darwin host support injected so the reader runs on any host.
    const session = composeBinarySession(new AnalysisProviderRegistry([]), [
      new ArtifactProvider({}),
      new NativeMacOSProvider({}, new NativeFixtureRunner(), "darwin"),
    ]);
    onTestFinished(async () => {
      const closed = await session.close();
      if (!closed.ok) throw closed.error;
    });
    const client = await mcp.connect(
      createServer({ kind: "session", session }),
    );
    const opened = await client.callTool({
      name: "open_binary",
      arguments: { path: app },
    });
    expect(opened.isError, JSON.stringify(opened.content)).not.toBe(true);

    const result = await client.callTool({
      name: "trace_native_ui_action",
      arguments: { action: selector },
    });
    expect(result.isError, JSON.stringify(result.content)).not.toBe(true);
    const trace = z
      .object({ normalized_result: nativeInvestigationTraceSchema })
      .parse(result.structuredContent).normalized_result;
    const handlerId = `native:function:${implementationAddress}`;
    const handler = trace.nodes.find(({ id }) => id === handlerId);
    expect(handler?.location).toEqual({
      address: implementationAddress,
      file_offset: null,
    });
    expect(handler?.evidence).toContainEqual(
      expect.objectContaining({
        kind: "binary_metadata",
        location: {
          address: methodEntryAddress,
          file_offset: sliceOffset + methodEntrySliceOffset,
        },
      }),
    );
    expect(trace.edges).toContainEqual(
      expect.objectContaining({
        relation: "objc_dispatch",
        resolution: "resolved",
        to: handlerId,
      }),
    );
  },
);

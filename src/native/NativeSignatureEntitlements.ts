import { parseXmlPropertyList } from "../domain/propertyListKeys.js";
import { jsonValueSchema, type JsonValue } from "../domain/jsonValue.js";

/** Parse the XML entitlement document within codesign output, retaining omission evidence. */
export const parseSignatureEntitlements = (
  output: string,
): { readonly value: JsonValue; readonly omittedPrototypeKeys: number } => {
  const start = output.indexOf("<?xml");
  const end = output.lastIndexOf("</plist>");
  if (start < 0 || end < start) return { value: null, omittedPrototypeKeys: 0 };
  const { value, omittedPrototypeKeys } = parseXmlPropertyList(
    output.slice(start, end + "</plist>".length),
  );
  return { value: jsonValueSchema.parse(value), omittedPrototypeKeys };
};

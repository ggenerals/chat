import { createHash } from "node:crypto";
const pwd = process.argv[2];
if (!pwd) {
  console.error("用法: node scripts/hash.mjs <密码>");
  process.exit(1);
}
console.log(createHash("sha256").update(pwd, "utf8").digest("hex"));
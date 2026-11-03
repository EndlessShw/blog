'use strict';

const fs = require('node:fs/promises');
const path = require('node:path');
const { inspect, writeMissingDates } = require('../lib/article-timestamps');

async function main(args) {
  const options = { fetch: args.includes('--fetch') };
  const rootIndex = args.indexOf('--root');
  const root = path.resolve(rootIndex >= 0 ? args[rootIndex + 1] : path.join(__dirname, '..'));
  const selected = args.flatMap((arg, i) => arg === '--file' ? [args[i + 1]] : []);
  if (selected.length) options.files = selected;
  const report = await inspect(root, options);
  const outputIndex = args.indexOf('--output');
  if (args.includes('--write-missing-dates')) report.written = await writeMissingDates(root, report);
  if (outputIndex >= 0) {
    await fs.writeFile(path.resolve(args[outputIndex + 1]), JSON.stringify(report, null, 2) + '\n');
    console.log(`日期报告已保存：${args[outputIndex + 1]}`);
  } else console.log(JSON.stringify(report, null, 2));
  return report;
}

if (require.main === module) main(process.argv.slice(2)).catch(error => {
  console.error(`[article-timestamps] ${error.message}`);
  process.exitCode = 1;
});

module.exports = { main };

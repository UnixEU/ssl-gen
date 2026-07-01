const { spawn } = require("child_process");
const path = require("path");

let lastOutput = "";
let running = false;

function runScript(scriptPath, options = {}) {
  const {
    env = process.env,
    args = [],
    cwd = path.dirname(scriptPath),
  } = options;

  return new Promise((resolve, reject) => {
    running = true;
    const chunks = [];

    const child = spawn("/bin/sh", [scriptPath, ...args], {
      cwd,
      env,
    });

    child.stdout.on("data", (chunk) => {
      chunks.push(chunk);
    });

    child.stderr.on("data", (chunk) => {
      chunks.push(chunk);
    });

    child.on("error", (error) => {
      running = false;
      reject(error);
    });

    child.on("close", (code) => {
      running = false;
      const output = Buffer.concat(chunks).toString("utf8");
      lastOutput = output;

      resolve({
        code: code ?? 1,
        output,
        success: code === 0,
      });
    });
  });
}

function getLastOutput() {
  return lastOutput;
}

function isRunning() {
  return running;
}

module.exports = {
  runScript,
  getLastOutput,
  isRunning,
};
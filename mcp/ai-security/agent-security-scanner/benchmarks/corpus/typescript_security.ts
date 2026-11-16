/**
 * Benchmark corpus: TypeScript security patterns.
 * Tests static detection of common web and Node.js vulnerabilities.
 */

import * as crypto from "crypto";
import * as fs from "fs";
import * as path from "path";
import { execSync, exec } from "child_process";
import express, { Request, Response } from "express";

const app = express();

// ---------------------------------------------------------------------------
// eval() of user input
// ---------------------------------------------------------------------------

app.get("/calc", (req: Request, res: Response) => {
  const expr: string = req.query.expr as string;

  // VULN: typescript.lang.security.eval-injection
  const result = eval(expr);

  // VULN: typescript.lang.security.eval-injection
  const fn = new Function("return " + expr);

  // SAFE: typescript.lang.security.eval-injection
  const safeResult = Number.parseFloat(expr);
  res.json({ result: safeResult });
});

// ---------------------------------------------------------------------------
// innerHTML XSS
// ---------------------------------------------------------------------------

function renderComment(userComment: string): void {
  const container = document.getElementById("comments")!;

  // VULN: typescript.browser.security.innerHTML-xss
  container.innerHTML = "<div>" + userComment + "</div>";

  // SAFE: typescript.browser.security.innerHTML-xss
  const div = document.createElement("div");
  div.textContent = userComment;
  container.appendChild(div);
}

// ---------------------------------------------------------------------------
// Prototype Pollution
// ---------------------------------------------------------------------------

function mergeDeep(target: any, source: any): any {
  for (const key in source) {
    // VULN: typescript.lang.security.prototype-pollution
    if (key === "__proto__" || key === "constructor" || key === "prototype") {
      target[key] = source[key];  // allows pollution
    }
    if (typeof source[key] === "object") {
      target[key] = mergeDeep(target[key] || {}, source[key]);
    } else {
      target[key] = source[key];
    }
  }
  return target;
}

function mergeSafe(target: any, source: any): any {
  for (const key in source) {
    // SAFE: typescript.lang.security.prototype-pollution
    if (key === "__proto__" || key === "constructor" || key === "prototype") {
      continue;  // skip dangerous keys
    }
    if (typeof source[key] === "object") {
      target[key] = mergeSafe(target[key] || {}, source[key]);
    } else {
      target[key] = source[key];
    }
  }
  return target;
}

// ---------------------------------------------------------------------------
// Insecure Cryptography
// ---------------------------------------------------------------------------

function hashPassword(password: string): string {
  // VULN: typescript.lang.security.insecure-hash
  return crypto.createHash("md5").update(password).digest("hex");
}

function hashPasswordSafe(password: string): string {
  // SAFE: typescript.lang.security.insecure-hash
  return crypto.createHash("sha256").update(password).digest("hex");
}

// ---------------------------------------------------------------------------
// Hardcoded Secrets
// ---------------------------------------------------------------------------

// VULN: typescript.lang.security.hardcoded-secret
const API_KEY = "sk-live-4f3c9a7b2d1e8f5c6a0b3d4e7f8a9c2d5e6f7a8b";

// VULN: typescript.lang.security.hardcoded-secret
const config = {
  database_password: "SuperS3cret!Pr0duction",
  aws_secret_key: "AKIAIOSFODNN7EXAMPLE+wJalrXUtnFEMI/K7MDENG",
};

// SAFE: typescript.lang.security.hardcoded-secret
const safeConfig = {
  api_key: process.env.API_KEY,
  database_password: process.env.DB_PASSWORD,
};

// ---------------------------------------------------------------------------
// Command Injection
// ---------------------------------------------------------------------------

app.get("/deploy", (req: Request, res: Response) => {
  const branch: string = req.query.branch as string;

  // VULN: typescript.lang.security.command-injection
  execSync("git checkout " + branch + " && ./deploy.sh");

  // SAFE: typescript.lang.security.command-injection
  execSync(`git checkout -- .`, { cwd: "/safe/repo" });
  res.send("deployed");
});

// ---------------------------------------------------------------------------
// Path Traversal
// ---------------------------------------------------------------------------

app.get("/file", (req: Request, res: Response) => {
  const filename: string = req.query.name as string;

  // VULN: typescript.lang.security.path-traversal
  const content = fs.readFileSync("/uploads/" + filename, "utf-8");

  // SAFE: typescript.lang.security.path-traversal
  const safeName = path.basename(filename);
  const safeContent = fs.readFileSync(path.join("/uploads", safeName), "utf-8");
  res.send(safeContent);
});

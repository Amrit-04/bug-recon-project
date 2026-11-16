import { spawn } from 'node:child_process';
import path from 'node:path';
import http from 'node:http';
import { fileURLToPath } from 'node:url';
import { setupTestData } from './setup-test-data.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const webDir = path.resolve(__dirname, '..');
const repoRoot = path.resolve(webDir, '..');

const { runsDir, scopePath } = setupTestData(webDir);
const binPath = path.join(repoRoot, process.platform === 'win32' ? 'scoutr.exe' : 'scoutr');

console.log(`Starting Scoutr backend: ${binPath}`);
const child = spawn(
  binPath,
  ['ui', '--port', '8765', '--host', '127.0.0.1', '--no-browser', '--runs-dir', runsDir, '--scope', scopePath],
  {
    cwd: repoRoot,
    stdio: 'inherit'
  }
);

child.on('error', (err) => {
  console.error('Failed to spawn scoutr process:', err);
  process.exit(1);
});

child.on('exit', (code, signal) => {
  console.log(`Scoutr process exited with code ${code}, signal ${signal}`);
});

function pollReady(attemptsLeft) {
  if (attemptsLeft <= 0) {
    console.error('Scoutr backend did not become ready in time.');
    child.kill();
    process.exit(1);
  }

  const req = http.get('http://127.0.0.1:8765/api/status', (res) => {
    if (res.statusCode === 200) {
      console.log('Scoutr test server is READY on http://127.0.0.1:8765');
    } else {
      setTimeout(() => pollReady(attemptsLeft - 1), 300);
    }
  });

  req.on('error', () => {
    setTimeout(() => pollReady(attemptsLeft - 1), 300);
  });
}

pollReady(40);

const cleanExit = () => {
  try {
    child.kill();
  } catch (_) {}
  process.exit(0);
};

process.on('SIGINT', cleanExit);
process.on('SIGTERM', cleanExit);
process.on('exit', cleanExit);

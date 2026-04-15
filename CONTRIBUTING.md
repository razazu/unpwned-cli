# Contributing to UNPWNED CLI

Thanks for your interest in contributing!

## Getting Started

1. Fork and clone the repo
2. Install dependencies: `npm install`
3. Run tests: `npm test`
4. Make your changes
5. Run tests again: `npm test`
6. Submit a PR

## Development

```bash
npm run dev      # Watch mode (auto-rebuild)
npm run test     # Run tests
npm run lint     # Type check
npm run build    # Build for production
```

## Adding a Scanner

1. Create `src/scanners/your-scanner.ts` implementing `ScanResult`
2. Create `src/scanners/your-scanner.test.ts` with tests
3. Register in `src/cli.ts` scanner configs
4. Add weight in `src/scoring.ts`

## Guidelines

- TypeScript strict mode
- Tests required for new scanners
- Keep dependencies minimal
- No comments unless logic is non-obvious

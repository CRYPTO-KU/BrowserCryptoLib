// jest.config.js
module.exports = {
	preset: 'ts-jest/presets/default-esm', // Use ts-jest with support for ESM
	testEnvironment: 'node', // Set test environment to Node.js
	extensionsToTreatAsEsm: ['.ts'], // Treat .ts files as ES modules
	transform: {
		'^.+\\.ts$': ['ts-jest', { useESM: true }], // Transform TypeScript using ts-jest with ESM support
	},
	globals: {
		'ts-jest': {
			useESM: true, // Enable ESM for ts-jest
		},
	},
};

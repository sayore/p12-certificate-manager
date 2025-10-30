const fs = require('fs');
const path = require('path');
const { createCA, listCAs, caBaseDir } = require('../services/caService');

// Mock the utils module to prevent actual command execution
jest.mock('../services/utils', () => ({
  runCommand: jest.fn().mockResolvedValue(),
}));

const testCaName = 'test-ca';
const testCaPassword = 'test-password';
const testCaDetails = {
  country: 'US',
  state: 'California',
  locality: 'San Francisco',
  organization: 'Test Inc.',
};

describe('caService', () => {
  beforeEach(() => {
    // Clean up before each test
    const caDir = path.join(caBaseDir, testCaName);
    if (fs.existsSync(caDir)) {
      fs.rmSync(caDir, { recursive: true, force: true });
    }
  });

  describe('createCA', () => {
    it('should create a new CA with valid parameters', async () => {
      await createCA(testCaName, testCaPassword, testCaDetails);
      const caDir = path.join(caBaseDir, testCaName);
      expect(fs.existsSync(caDir)).toBe(true);
    });

    it('should throw an error for an invalid CA name', async () => {
      await expect(createCA('invalid name', testCaPassword, testCaDetails)).rejects.toThrow('Invalid CA name');
    });

    it('should throw an error if the CA already exists', async () => {
      // Ensure the CA is created first
      await createCA(testCaName, testCaPassword, testCaDetails);
      await expect(createCA(testCaName, testCaPassword, testCaDetails)).rejects.toThrow('CA with this name already exists');
    });
  });

  describe('listCAs', () => {
    beforeEach(() => {
      // Clean up before each test
      fs.readdirSync(caBaseDir).forEach(file => {
        const filePath = path.join(caBaseDir, file);
        if (fs.statSync(filePath).isDirectory()) {
          fs.rmSync(filePath, { recursive: true, force: true });
        }
      });
    });

    it('should return an empty array when no CAs exist', () => {
      expect(listCAs()).toEqual([]);
    });

    it('should return an array with one CA when one CA exists', async () => {
      await createCA(testCaName, testCaPassword, testCaDetails);
      expect(listCAs()).toEqual([{ name: testCaName }]);
    });
  });
});

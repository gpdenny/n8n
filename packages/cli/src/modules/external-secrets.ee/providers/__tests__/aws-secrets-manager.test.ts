import { SecretsManager } from '@aws-sdk/client-secrets-manager';
import { mock } from 'jest-mock-extended';

import { AwsSecretsManager, type AwsSecretsManagerContext } from '../aws-secrets-manager';

jest.mock('@aws-sdk/client-secrets-manager');

describe('AwsSecretsManager', () => {
	const region = 'eu-central-1';
	const accessKeyId = 'FAKE-ACCESS-KEY-ID';
	const secretAccessKey = 'FAKE-SECRET';

	const context = mock<AwsSecretsManagerContext>();
	const listSecretsSpy = jest.spyOn(SecretsManager.prototype, 'listSecrets');
	const batchGetSpy = jest.spyOn(SecretsManager.prototype, 'batchGetSecretValue');

	let awsSecretsManager: AwsSecretsManager;

	beforeEach(() => {
		jest.resetAllMocks();

		awsSecretsManager = new AwsSecretsManager();
	});

	describe('IAM User authentication', () => {
		it('should fail to connect with invalid credentials', async () => {
			context.settings = {
				region,
				authMethod: 'iamUser',
				accessKeyId: 'invalid',
				secretAccessKey: 'invalid',
			};

			await awsSecretsManager.init(context);

			listSecretsSpy.mockImplementation(() => {
				throw new Error('Invalid credentials');
			});

			await awsSecretsManager.connect();

			expect(awsSecretsManager.state).toBe('error');
		});
	});

	it('should update cached secrets', async () => {
		context.settings = {
			region,
			authMethod: 'iamUser',
			accessKeyId,
			secretAccessKey,
		};

		await awsSecretsManager.init(context);

		listSecretsSpy.mockImplementation(async () => {
			return {
				SecretList: [{ Name: 'secret1' }, { Name: 'secret2' }],
			};
		});

		batchGetSpy.mockImplementation(async () => {
			return {
				SecretValues: [
					{ Name: 'secret1', SecretString: 'value1' },
					{ Name: 'secret2', SecretString: 'value2' },
				],
			};
		});

		await awsSecretsManager.update();

		expect(listSecretsSpy).toHaveBeenCalledTimes(1);
		expect(batchGetSpy).toHaveBeenCalledWith({
			SecretIdList: expect.arrayContaining(['secret1', 'secret2']),
		});

		expect(awsSecretsManager.getSecret('secret1')).toBe('value1');
		expect(awsSecretsManager.getSecret('secret2')).toBe('value2');
	});

	it('should properly batch secret requests', async () => {
		context.settings = {
			region,
			authMethod: 'iamUser',
			accessKeyId,
			secretAccessKey,
		};
		await awsSecretsManager.init(context);

		// Generate 25 secrets to test batching (default batch size is 20)
		const secretsList = Array(25)
			.fill(0)
			.map((_, i) => ({ Name: `secret${i}` }));

		listSecretsSpy.mockImplementation(async () => {
			return { SecretList: secretsList };
		});

		batchGetSpy.mockImplementation(async (params) => {
			const secretValues = (params.SecretIdList || []).map((secretId) => ({
				Name: secretId,
				SecretString: `${secretId}-value`,
			}));
			return { SecretValues: secretValues };
		});

		await awsSecretsManager.update();

		// Should have been called twice for 25 secrets with batch size 20
		expect(batchGetSpy).toHaveBeenCalledTimes(2);

		// First batch should have 20 secrets
		expect(batchGetSpy.mock.calls[0][0].SecretIdList?.length).toBe(20);

		// Second batch should have 5 secrets
		expect(batchGetSpy.mock.calls[1][0].SecretIdList?.length).toBe(5);

		// Check a few secrets
		expect(awsSecretsManager.getSecret('secret0')).toBe('secret0-value');
		expect(awsSecretsManager.getSecret('secret24')).toBe('secret24-value');
	});

	it('should handle pagination in listing secrets', async () => {
		context.settings = {
			region,
			authMethod: 'iamUser',
			accessKeyId,
			secretAccessKey,
		};
		await awsSecretsManager.init(context);

		// First call with NextToken
		listSecretsSpy.mockImplementationOnce(async () => {
			return {
				SecretList: [{ Name: 'secret1' }, { Name: 'secret2' }],
				NextToken: 'next-page-token',
			};
		});

		// Second call with no NextToken
		listSecretsSpy.mockImplementationOnce(async () => {
			return {
				SecretList: [{ Name: 'secret3' }],
			};
		});

		batchGetSpy.mockImplementation(async (params) => {
			const secretValues = [];
			for (const secretId of params.SecretIdList || []) {
				secretValues.push({
					Name: secretId,
					SecretString: `${secretId}-value`,
				});
			}
			return { SecretValues: secretValues };
		});

		await awsSecretsManager.update();

		expect(listSecretsSpy).toHaveBeenCalledWith({ NextToken: 'next-page-token' });
		expect(listSecretsSpy).toHaveBeenCalledWith({ NextToken: undefined });

		expect(awsSecretsManager.getSecret('secret1')).toBe('secret1-value');
		expect(awsSecretsManager.getSecret('secret2')).toBe('secret2-value');
		expect(awsSecretsManager.getSecret('secret3')).toBe('secret3-value');
	});

	describe('Filter functionality', () => {
		it('should apply valid tag-key filter', async () => {
			context.settings = {
				region,
				authMethod: 'iamUser',
				accessKeyId,
				secretAccessKey,
				filterJson: '[{"Key": "tag-key", "Values": ["Environment"]}]',
			};

			await awsSecretsManager.init(context);

			listSecretsSpy.mockImplementation(async () => {
				return {
					SecretList: [{ Name: 'filtered-secret1' }, { Name: 'filtered-secret2' }],
				};
			});

			batchGetSpy.mockImplementation(async () => {
				return {
					SecretValues: [
						{ Name: 'filtered-secret1', SecretString: 'filtered-value1' },
						{ Name: 'filtered-secret2', SecretString: 'filtered-value2' },
					],
				};
			});

			await awsSecretsManager.update();

			expect(listSecretsSpy).toHaveBeenCalledWith({
				NextToken: undefined,
				Filters: [{ Key: 'tag-key', Values: ['Environment'] }],
			});

			expect(awsSecretsManager.getSecret('filtered-secret1')).toBe('filtered-value1');
			expect(awsSecretsManager.getSecret('filtered-secret2')).toBe('filtered-value2');
		});

		it('should apply valid tag-value filter', async () => {
			context.settings = {
				region,
				authMethod: 'iamUser',
				accessKeyId,
				secretAccessKey,
				filterJson: '[{"Key": "tag-value", "Values": ["Production", "Staging"]}]',
			};

			await awsSecretsManager.init(context);

			listSecretsSpy.mockImplementation(async () => {
				return {
					SecretList: [{ Name: 'prod-secret' }],
				};
			});

			batchGetSpy.mockImplementation(async () => {
				return {
					SecretValues: [{ Name: 'prod-secret', SecretString: 'prod-value' }],
				};
			});

			await awsSecretsManager.update();

			expect(listSecretsSpy).toHaveBeenCalledWith({
				NextToken: undefined,
				Filters: [{ Key: 'tag-value', Values: ['Production', 'Staging'] }],
			});

			expect(awsSecretsManager.getSecret('prod-secret')).toBe('prod-value');
		});

		it('should apply multiple filters', async () => {
			context.settings = {
				region,
				authMethod: 'iamUser',
				accessKeyId,
				secretAccessKey,
				filterJson:
					'[{"Key": "tag-key", "Values": ["Environment"]}, {"Key": "name", "Values": ["db-*"]}]',
			};

			await awsSecretsManager.init(context);

			listSecretsSpy.mockImplementation(async () => {
				return {
					SecretList: [{ Name: 'db-secret' }],
				};
			});

			batchGetSpy.mockImplementation(async () => {
				return {
					SecretValues: [{ Name: 'db-secret', SecretString: 'db-value' }],
				};
			});

			await awsSecretsManager.update();

			expect(listSecretsSpy).toHaveBeenCalledWith({
				NextToken: undefined,
				Filters: [
					{ Key: 'tag-key', Values: ['Environment'] },
					{ Key: 'name', Values: ['db-*'] },
				],
			});

			expect(awsSecretsManager.getSecret('db-secret')).toBe('db-value');
		});

		it('should handle empty filter JSON', async () => {
			context.settings = {
				region,
				authMethod: 'iamUser',
				accessKeyId,
				secretAccessKey,
				filterJson: '',
			};

			await awsSecretsManager.init(context);

			listSecretsSpy.mockImplementation(async () => {
				return {
					SecretList: [{ Name: 'all-secret' }],
				};
			});

			batchGetSpy.mockImplementation(async () => {
				return {
					SecretValues: [{ Name: 'all-secret', SecretString: 'all-value' }],
				};
			});

			await awsSecretsManager.update();

			expect(listSecretsSpy).toHaveBeenCalledWith({
				NextToken: undefined,
				Filters: undefined,
			});

			expect(awsSecretsManager.getSecret('all-secret')).toBe('all-value');
		});

		it('should handle empty array filter JSON', async () => {
			context.settings = {
				region,
				authMethod: 'iamUser',
				accessKeyId,
				secretAccessKey,
				filterJson: '[]',
			};

			await awsSecretsManager.init(context);

			listSecretsSpy.mockImplementation(async () => {
				return {
					SecretList: [{ Name: 'no-filter-secret' }],
				};
			});

			batchGetSpy.mockImplementation(async () => {
				return {
					SecretValues: [{ Name: 'no-filter-secret', SecretString: 'no-filter-value' }],
				};
			});

			await awsSecretsManager.update();

			expect(listSecretsSpy).toHaveBeenCalledWith({
				NextToken: undefined,
				Filters: undefined,
			});

			expect(awsSecretsManager.getSecret('no-filter-secret')).toBe('no-filter-value');
		});

		it('should handle invalid JSON gracefully', async () => {
			context.settings = {
				region,
				authMethod: 'iamUser',
				accessKeyId,
				secretAccessKey,
				filterJson: 'invalid json',
			};

			await awsSecretsManager.init(context);

			listSecretsSpy.mockImplementation(async () => {
				return {
					SecretList: [{ Name: 'fallback-secret' }],
				};
			});

			batchGetSpy.mockImplementation(async () => {
				return {
					SecretValues: [{ Name: 'fallback-secret', SecretString: 'fallback-value' }],
				};
			});

			await awsSecretsManager.update();

			// Should fall back to no filters when JSON is invalid
			expect(listSecretsSpy).toHaveBeenCalledWith({
				NextToken: undefined,
				Filters: undefined,
			});

			expect(awsSecretsManager.getSecret('fallback-secret')).toBe('fallback-value');
		});

		it('should handle non-array JSON gracefully', async () => {
			context.settings = {
				region,
				authMethod: 'iamUser',
				accessKeyId,
				secretAccessKey,
				filterJson: '{"not": "an array"}',
			};

			await awsSecretsManager.init(context);

			listSecretsSpy.mockImplementation(async () => {
				return {
					SecretList: [{ Name: 'fallback-secret2' }],
				};
			});

			batchGetSpy.mockImplementation(async () => {
				return {
					SecretValues: [{ Name: 'fallback-secret2', SecretString: 'fallback-value2' }],
				};
			});

			await awsSecretsManager.update();

			// Should fall back to no filters when JSON is not an array
			expect(listSecretsSpy).toHaveBeenCalledWith({
				NextToken: undefined,
				Filters: undefined,
			});

			expect(awsSecretsManager.getSecret('fallback-secret2')).toBe('fallback-value2');
		});

		it('should handle invalid filter structure gracefully', async () => {
			context.settings = {
				region,
				authMethod: 'iamUser',
				accessKeyId,
				secretAccessKey,
				filterJson: '[{"invalid": "structure"}]',
			};

			await awsSecretsManager.init(context);

			listSecretsSpy.mockImplementation(async () => {
				return {
					SecretList: [{ Name: 'fallback-secret3' }],
				};
			});

			batchGetSpy.mockImplementation(async () => {
				return {
					SecretValues: [{ Name: 'fallback-secret3', SecretString: 'fallback-value3' }],
				};
			});

			await awsSecretsManager.update();

			// Should fall back to no filters when filter structure is invalid
			expect(listSecretsSpy).toHaveBeenCalledWith({
				NextToken: undefined,
				Filters: undefined,
			});

			expect(awsSecretsManager.getSecret('fallback-secret3')).toBe('fallback-value3');
		});

		it('should handle unsupported filter keys gracefully', async () => {
			context.settings = {
				region,
				authMethod: 'iamUser',
				accessKeyId,
				secretAccessKey,
				filterJson: '[{"Key": "unsupported-key", "Values": ["value"]}]',
			};

			await awsSecretsManager.init(context);

			listSecretsSpy.mockImplementation(async () => {
				return {
					SecretList: [{ Name: 'fallback-secret4' }],
				};
			});

			batchGetSpy.mockImplementation(async () => {
				return {
					SecretValues: [{ Name: 'fallback-secret4', SecretString: 'fallback-value4' }],
				};
			});

			await awsSecretsManager.update();

			// Should fall back to no filters when filter key is unsupported
			expect(listSecretsSpy).toHaveBeenCalledWith({
				NextToken: undefined,
				Filters: undefined,
			});

			expect(awsSecretsManager.getSecret('fallback-secret4')).toBe('fallback-value4');
		});

		it('should handle mixed valid and invalid filters gracefully', async () => {
			context.settings = {
				region,
				authMethod: 'iamUser',
				accessKeyId,
				secretAccessKey,
				filterJson: '[{"Key": "tag-key", "Values": ["Environment"]}, {"invalid": "filter"}]',
			};

			await awsSecretsManager.init(context);

			listSecretsSpy.mockImplementation(async () => {
				return {
					SecretList: [{ Name: 'fallback-secret5' }],
				};
			});

			batchGetSpy.mockImplementation(async () => {
				return {
					SecretValues: [{ Name: 'fallback-secret5', SecretString: 'fallback-value5' }],
				};
			});

			await awsSecretsManager.update();

			// Should fall back to no filters when any filter is invalid
			expect(listSecretsSpy).toHaveBeenCalledWith({
				NextToken: undefined,
				Filters: undefined,
			});

			expect(awsSecretsManager.getSecret('fallback-secret5')).toBe('fallback-value5');
		});

		it('should handle filters with non-string values gracefully', async () => {
			context.settings = {
				region,
				authMethod: 'iamUser',
				accessKeyId,
				secretAccessKey,
				filterJson: '[{"Key": "tag-key", "Values": ["Environment", 123]}]',
			};

			await awsSecretsManager.init(context);

			listSecretsSpy.mockImplementation(async () => {
				return {
					SecretList: [{ Name: 'fallback-secret6' }],
				};
			});

			batchGetSpy.mockImplementation(async () => {
				return {
					SecretValues: [{ Name: 'fallback-secret6', SecretString: 'fallback-value6' }],
				};
			});

			await awsSecretsManager.update();

			// Should fall back to no filters when values are not all strings
			expect(listSecretsSpy).toHaveBeenCalledWith({
				NextToken: undefined,
				Filters: undefined,
			});

			expect(awsSecretsManager.getSecret('fallback-secret6')).toBe('fallback-value6');
		});
	});
});

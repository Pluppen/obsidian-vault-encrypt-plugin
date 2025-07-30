import { App, Plugin, Setting, Modal, Notice, TFile, TFolder, Menu, PluginSettingTab } from 'obsidian';

interface FilenameMapping {
  original: string;
  encrypted: string;
  fileIndex: number;
  sizePadding: number;
  originalSize: number;
  timestamp: string;
}

interface EncryptionResult {
  encryptedFiles: string[];
  mappingCreated: boolean;
}

interface ParsedEncryptedFile {
  content: string | null;
}

interface ParsedMappingFile {
  content: string | null;
}

interface EncryptionBatch {
  files: TFile[];
  startIndex: number;
  endIndex: number;
}

type StatusCallback = (current: number, total: number, status: string) => void;

class SecureVaultEncryption {
  protected app: App;
  protected readonly algorithm = 'AES-GCM';
  protected readonly ivLength = 12;  // 96 bits (recommended for GCM)
  protected readonly saltLength = 32; // 256 bits
  protected readonly iterations = 100000; // PBKDF2 iterations
  private readonly batchSize = 10; // Process 10 files concurrently
  private readonly paddingSizes = [1024, 4096, 16384, 32768]; // Standard padding sizes
  private masterKey: CryptoKey | null = null;

  constructor(app: App) {
    this.app = app;
  }

  private async deriveMasterKey(password: string, salt: Uint8Array): Promise<CryptoKey> {
    const encoder = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey(
      'raw',
      encoder.encode(password),
      'PBKDF2',
      false,
      ['deriveBits']
    );

    const derivedBits = await crypto.subtle.deriveBits(
      {
        name: 'PBKDF2',
        salt: salt,
        iterations: this.iterations,
        hash: 'SHA-256'
      },
      keyMaterial,
      256
    );

    return crypto.subtle.importKey(
      'raw',
      derivedBits,
      'HKDF',
      false,
      ['deriveKey']
    );
  }

  private async deriveFileKey(masterKey: CryptoKey, fileIndex: number): Promise<CryptoKey> {
    const info = new TextEncoder().encode(`file-${fileIndex}`);
    
    return crypto.subtle.deriveKey(
      {
        name: 'HKDF',
        hash: 'SHA-256',
        salt: new Uint8Array(0),
        info: info
      },
      masterKey,
      { name: this.algorithm, length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
  }

  private async encryptTextWithFileKey(text: string, fileKey: CryptoKey): Promise<string> {
    const encoder = new TextEncoder();
    const data = encoder.encode(text);
    
    const iv = crypto.getRandomValues(new Uint8Array(this.ivLength));
    
    const encrypted = await crypto.subtle.encrypt(
      { name: this.algorithm, iv: iv },
      fileKey,
      data
    );
    
    const result = new Uint8Array(iv.length + encrypted.byteLength);
    result.set(iv, 0);
    result.set(new Uint8Array(encrypted), iv.length);
    
    return this.arrayBufferToBase64(result);
  }

  private async decryptTextWithFileKey(encryptedBase64: string, fileKey: CryptoKey): Promise<string> {
    const encryptedData = this.base64ToArrayBuffer(encryptedBase64);
    const dataView = new Uint8Array(encryptedData);
    
    const iv = dataView.slice(0, this.ivLength);
    const encrypted = dataView.slice(this.ivLength);
    
    const decrypted = await crypto.subtle.decrypt(
      { name: this.algorithm, iv: iv },
      fileKey,
      encrypted
    );
    
    const decoder = new TextDecoder();
    return decoder.decode(decrypted);
  }

  private calculateSizePadding(originalSize: number): number {
    for (const paddingSize of this.paddingSizes) {
      if (originalSize <= paddingSize * 0.8) { // Use 80% of padding size
        return paddingSize - originalSize;
      }
    }
    const boundary = 65536;
    return boundary - (originalSize % boundary);
  }

  private addSizePadding(content: string, paddingSize: number): string {
    if (paddingSize <= 0) return content;
    
    const padding = '<!--PADDING:' + 'X'.repeat(paddingSize - 20) + '-->';
    return content + '\n\n' + padding;
  }

  private removeSizePadding(content: string): string {
    const paddingRegex = /\n\n<!--PADDING:X+-->$/;
    return content.replace(paddingRegex, '');
  }

  async encryptVault(password: string, statusCallback?: StatusCallback): Promise<EncryptionResult> {
    const startTime = Date.now();
    const allFiles = this.app.vault.getFiles();
    
    const filesToEncrypt = allFiles.filter(f => 
      !f.name.startsWith('enc_') && 
      f.name !== 'vault_mapping.encrypted'
    );

    if (filesToEncrypt.length === 0) {
      throw new Error('No files to encrypt');
    }

    statusCallback?.(0, filesToEncrypt.length, 'Deriving master key...');

    const masterSalt = crypto.getRandomValues(new Uint8Array(this.saltLength));
    this.masterKey = await this.deriveMasterKey(password, masterSalt);

    const batches: EncryptionBatch[] = [];
    for (let i = 0; i < filesToEncrypt.length; i += this.batchSize) {
      batches.push({
        files: filesToEncrypt.slice(i, i + this.batchSize),
        startIndex: i,
        endIndex: Math.min(i + this.batchSize, filesToEncrypt.length)
      });
    }

    const filenameMapping: FilenameMapping[] = [];
    const encryptedFiles: string[] = [];
    let processed = 0;

    for (let batchIndex = 0; batchIndex < batches.length; batchIndex++) {
      const batch = batches[batchIndex];
      
      statusCallback?.(processed, filesToEncrypt.length, 
        `Encrypting batch ${batchIndex + 1}/${batches.length}...`);

      // Process batch in parallel
      const batchPromises = batch.files.map(async (file, indexInBatch) => {
        const fileIndex = batch.startIndex + indexInBatch;
        
        try {
          const encryptedFilename = this.generateEncryptedFilename();
          
          const originalContent = await this.app.vault.read(file);
          const originalSize = new TextEncoder().encode(originalContent).length;
          
          const sizePadding = this.calculateSizePadding(originalSize);
          const paddedContent = this.addSizePadding(originalContent, sizePadding);
          
          const fileKey = await this.deriveFileKey(this.masterKey!, fileIndex);
          const encryptedContent = await this.encryptTextWithFileKey(paddedContent, fileKey);
          
          const mappingEntry: FilenameMapping = {
            original: file.path,
            encrypted: encryptedFilename,
            fileIndex: fileIndex,
            sizePadding: sizePadding,
            originalSize: originalSize,
            timestamp: new Date().toISOString()
          };

          const formattedContent = this.formatAnonymousEncryptedFile(encryptedContent);
          
          return {
            file,
            encryptedFilename,
            formattedContent,
            mappingEntry
          };
          
        } catch (error) {
          throw new Error(`Failed to encrypt ${file.name}: ${error instanceof Error ? error.message : 'Unknown error'}`);
        }
      });

      const batchResults = await Promise.all(batchPromises);
      
      for (const result of batchResults) {
        await this.app.vault.create(result.encryptedFilename, result.formattedContent);
        await this.app.vault.delete(result.file);
        
        filenameMapping.push(result.mappingEntry);
        encryptedFiles.push(result.encryptedFilename);
        processed++;
      }
    }

    await this.removeAllFolders();

    statusCallback?.(processed, filesToEncrypt.length, 'Creating filename mapping...');
    
    const mappingData = {
      salt: Array.from(masterSalt),
      mappings: filenameMapping
    };
    
    const encryptedMapping = await this.encryptText(JSON.stringify(mappingData, null, 2), password);
    const mappingContent = this.formatMappingFile(encryptedMapping);
    await this.app.vault.create('vault_mapping.encrypted', mappingContent);

    this.masterKey = null;

    const totalTime = (Date.now() - startTime) / 1000;
    statusCallback?.(processed, filesToEncrypt.length, 
      `Encryption complete! (${totalTime.toFixed(1)}s, ${processed} files)`);
      
    return { encryptedFiles, mappingCreated: true };
  }

  async decryptVault(password: string, statusCallback?: StatusCallback): Promise<string[]> {
    const startTime = Date.now();
    
    statusCallback?.(0, 1, 'Reading filename mapping...');
    
    const mappingFile = this.app.vault.getAbstractFileByPath('vault_mapping.encrypted');
    if (!mappingFile || !(mappingFile instanceof TFile)) {
      throw new Error('Filename mapping not found. Cannot decrypt vault.');
    }
    
    const mappingContent = await this.app.vault.read(mappingFile);
    const { content: encryptedMapping } = this.parseMappingFile(mappingContent);
    
    if (!encryptedMapping) {
      throw new Error('Invalid mapping file format');
    }

    statusCallback?.(0, 1, 'Decrypting filename mapping...');
    
    let mappingData;
    try {
      const decryptedMappingJson = await this.decryptText(encryptedMapping, password);
      mappingData = JSON.parse(decryptedMappingJson);
    } catch (error) {
      throw new Error('Failed to decrypt mapping - invalid password');
    }

    const masterSalt = new Uint8Array(mappingData.salt);
    const filenameMapping: FilenameMapping[] = mappingData.mappings;
    
    statusCallback?.(0, 1, 'Deriving master key...');
    this.masterKey = await this.deriveMasterKey(password, masterSalt);

    const encryptedFiles = this.app.vault.getFiles().filter(f => 
      f.name.startsWith('enc_') && f.name.endsWith('.md')
    );

    const mappingByFilename = new Map(filenameMapping.map(m => [m.encrypted, m]));
    const validFiles = encryptedFiles.filter(f => mappingByFilename.has(f.name));
    
    const batches: TFile[][] = [];
    for (let i = 0; i < validFiles.length; i += this.batchSize) {
      batches.push(validFiles.slice(i, i + this.batchSize));
    }

    const decryptedFiles: string[] = [];
    let processed = 0;

    for (let batchIndex = 0; batchIndex < batches.length; batchIndex++) {
      const batch = batches[batchIndex];
      
      statusCallback?.(processed, validFiles.length, 
        `Decrypting batch ${batchIndex + 1}/${batches.length}...`);

      const batchPromises = batch.map(async (file) => {
        const mappingEntry = mappingByFilename.get(file.name);
        if (!mappingEntry) return null;

        try {
          const encryptedContent = await this.app.vault.read(file);
          const { content: encryptedData } = this.parseAnonymousEncryptedFile(encryptedContent);
          
          if (!encryptedData) {
            throw new Error('Invalid encrypted file format');
          }
          
          const fileKey = await this.deriveFileKey(this.masterKey!, mappingEntry.fileIndex);
          let decryptedContent = await this.decryptTextWithFileKey(encryptedData, fileKey);
          
          decryptedContent = this.removeSizePadding(decryptedContent);
          
          return {
            file,
            originalPath: mappingEntry.original,
            decryptedContent
          };
          
        } catch (error) {
          throw new Error(`Failed to decrypt ${file.name}: ${error instanceof Error ? error.message : 'Unknown error'}`);
        }
      });

      const batchResults = await Promise.all(batchPromises);
      
      for (const result of batchResults) {
        if (!result) continue;
        
        const dirPath = result.originalPath.substring(0, result.originalPath.lastIndexOf('/'));
        if (dirPath) {
          await this.ensureDirectoryExists(dirPath);
        }
        
        await this.app.vault.create(result.originalPath, result.decryptedContent);
        await this.app.vault.delete(result.file);
        
        decryptedFiles.push(result.originalPath);
        processed++;
      }
    }

    await this.app.vault.delete(mappingFile);
    this.masterKey = null;

    const totalTime = (Date.now() - startTime) / 1000;
    statusCallback?.(processed, validFiles.length, 
      `Decryption complete! Original structure restored. (${totalTime.toFixed(1)}s, ${processed} files)`);
      
    return decryptedFiles;
  }

  private formatAnonymousEncryptedFile(encryptedBase64: string): string {
    return `
> ⚠️ **This file contains encrypted data**  
> Use the Vault Encryption plugin to decrypt.

\`\`\`encrypted
${this.formatBase64WithLineBreaks(encryptedBase64)}
\`\`\`

`;
  }

  private formatMappingFile(encryptedMapping: string): string {
    return `
\`\`\`mapping
${this.formatBase64WithLineBreaks(encryptedMapping)}
\`\`\``;
  }

  private parseAnonymousEncryptedFile(content: string): ParsedEncryptedFile {
    const match = content.match(/```encrypted\n([\s\S]*?)\n```/);
    if (!match) {
      return { content: null };
    }
    return { content: match[1].replace(/\s/g, '') };
  }

  private parseMappingFile(content: string): ParsedMappingFile {
    const match = content.match(/```mapping\n([\s\S]*?)\n```/);
    if (!match) {
      return { content: null };
    }
    return { content: match[1].replace(/\s/g, '') };
  }

  private async removeAllFolders(): Promise<void> {
    const allFolders = this.app.vault.getAllLoadedFiles()
      .filter(f => f instanceof TFolder)
      .map(f => f as TFolder)
      .sort((a, b) => b.path.length - a.path.length);

    for (const folder of allFolders) {
      try {
        await this.app.vault.delete(folder);
      } catch (error) {
        console.debug(`Could not delete folder ${folder.path}:`, error);
      }
    }
  }

  private async ensureDirectoryExists(dirPath: string): Promise<void> {
    if (this.app.vault.getAbstractFileByPath(dirPath)) {
      return;
    }
    
    const folders = dirPath.split('/');
    let currentPath = '';
    
    for (const folder of folders) {
      currentPath += (currentPath ? '/' : '') + folder;
      if (!this.app.vault.getAbstractFileByPath(currentPath)) {
        await this.app.vault.createFolder(currentPath);
      }
    }
  }

  protected async deriveKey(password: string, salt: Uint8Array): Promise<CryptoKey> {
    const encoder = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey(
      'raw',
      encoder.encode(password),
      'PBKDF2',
      false,
      ['deriveBits', 'deriveKey']
    );

    return crypto.subtle.deriveKey(
      {
        name: 'PBKDF2',
        salt: salt,
        iterations: this.iterations,
        hash: 'SHA-256'
      },
      keyMaterial,
      { name: this.algorithm, length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
  }

  async encryptText(text: string, password: string): Promise<string> {
    try {
      const encoder = new TextEncoder();
      const data = encoder.encode(text);
      
      const salt = crypto.getRandomValues(new Uint8Array(this.saltLength));
      const iv = crypto.getRandomValues(new Uint8Array(this.ivLength));
      
      const key = await this.deriveKey(password, salt);
      
      const encrypted = await crypto.subtle.encrypt(
        { name: this.algorithm, iv: iv },
        key,
        data
      );
      
      const result = new Uint8Array(salt.length + iv.length + encrypted.byteLength);
      result.set(salt, 0);
      result.set(iv, salt.length);
      result.set(new Uint8Array(encrypted), salt.length + iv.length);
      
      return this.arrayBufferToBase64(result);
      
    } catch (error) {
      console.error('Encryption failed:', error);
      throw new Error(`Encryption failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  async decryptText(encryptedBase64: string, password: string): Promise<string> {
    try {
      const encryptedData = this.base64ToArrayBuffer(encryptedBase64);
      const dataView = new Uint8Array(encryptedData);
      
      const salt = dataView.slice(0, this.saltLength);
      const iv = dataView.slice(this.saltLength, this.saltLength + this.ivLength);
      const encrypted = dataView.slice(this.saltLength + this.ivLength);
      
      const key = await this.deriveKey(password, salt);
      
      const decrypted = await crypto.subtle.decrypt(
        { name: this.algorithm, iv: iv },
        key,
        encrypted
      );
      
      const decoder = new TextDecoder();
      return decoder.decode(decrypted);
      
    } catch (error) {
      console.error('Decryption failed:', error);
      throw new Error('Decryption failed: Invalid password or corrupted data');
    }
  }

  protected formatBase64WithLineBreaks(base64: string, lineLength: number = 64): string {
    const regex = new RegExp(`.{1,${lineLength}}`, 'g');
    const matches = base64.match(regex);
    return matches ? matches.join('\n') : base64;
  }

  protected arrayBufferToBase64(buffer: ArrayBuffer): string {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
  }

  protected base64ToArrayBuffer(base64: string): ArrayBuffer {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
  }

  protected generateEncryptedFilename(): string {
    const randomBytes = crypto.getRandomValues(new Uint8Array(16));
    const base64 = btoa(String.fromCharCode(...randomBytes))
      .replace(/[^a-zA-Z0-9]/g, '')
      .substring(0, 12);
    return `enc_${base64}.md`;
  }
}

class PasswordModal extends Modal {
  private title: string;
  private onSubmit: (password: string) => void;

  constructor(app: App, title: string, onSubmit: (password: string) => void) {
    super(app);
    this.title = title;
    this.onSubmit = onSubmit;
  }

  onOpen(): void {
    const { contentEl } = this;
    contentEl.createEl('h2', { text: this.title });

    const inputEl = contentEl.createEl('input', {
      type: 'password',
      placeholder: 'Enter vault password...',
	  cls: 'input-element'
    });
    
    const buttonContainer = contentEl.createDiv({cls: 'button-container'});
    const submitBtn = buttonContainer.createEl('button', { text: 'Submit' });
    const cancelBtn = buttonContainer.createEl('button', { text: 'Cancel' });

    submitBtn.onclick = () => {
      if (inputEl.value.length < 8) {
        new Notice('Password must be at least 8 characters long');
        return;
      }
      this.close();
      this.onSubmit(inputEl.value);
    };

    cancelBtn.onclick = () => this.close();

    inputEl.focus();
    inputEl.addEventListener('keypress', (e: KeyboardEvent) => {
      if (e.key === 'Enter') submitBtn.click();
    });
  }

  onClose(): void {
    const { contentEl } = this;
    contentEl.empty();
  }
}

interface VaultEncryptionSettings {
  encryptionIterations: number;
  showWarnings: boolean;
  autoBackup: boolean;
  autoEncryptOnClose: boolean;
  autoDecryptOnLoad: boolean;
  rememberPassword: boolean;
  passwordTimeout: number; // minutes
}

const DEFAULT_SETTINGS: VaultEncryptionSettings = {
  encryptionIterations: 100000,
  showWarnings: true,
  autoBackup: true,
  autoEncryptOnClose: false,
  autoDecryptOnLoad: false,
  rememberPassword: false,
  passwordTimeout: 30
};

export default class VaultEncryptionPlugin extends Plugin {
  private encryption!: SecureVaultEncryption;
  settings!: VaultEncryptionSettings;
  private isEncrypted: boolean = false;

  async onload(): Promise<void> {
    await this.loadSettings();
    
    this.encryption = new SecureVaultEncryption(this.app);

    this.checkVaultEncryptionStatus();

    this.addRibbonIcon('lock', 'Vault Encryption', (evt: MouseEvent) => {
      this.showEncryptionMenu(evt);
    });

    this.addCommand({
      id: 'encrypt-vault',
      name: 'Encrypt entire vault',
      callback: () => this.encryptVault()
    });

    this.addCommand({
      id: 'decrypt-vault', 
      name: 'Decrypt entire vault',
      callback: () => this.decryptVault()
    });

    this.addSettingTab(new VaultEncryptionSettingTab(this.app, this));
  }

  async loadSettings(): Promise<void> {
    this.settings = Object.assign({}, DEFAULT_SETTINGS, await this.loadData());
  }

  async saveSettings(): Promise<void> {
    await this.saveData(this.settings);
  }

  private checkVaultEncryptionStatus(): void {
    const mappingFile = this.app.vault.getAbstractFileByPath('vault_mapping.encrypted');
    const hasEncryptedFiles = this.app.vault.getFiles().some(f => f.name.startsWith('enc_'));
    this.isEncrypted = mappingFile !== null || hasEncryptedFiles;
  }

  showEncryptionMenu(evt: MouseEvent): void {
    const menu = new Menu();
    
    menu.addItem((item) =>
      item.setTitle('Encrypt Vault')
          .setIcon('lock')
          .onClick(() => this.encryptVault())
    );

    menu.addItem((item) =>
      item.setTitle('Decrypt Vault')
          .setIcon('unlock')
          .onClick(() => this.decryptVault())
    );

    menu.showAtMouseEvent(evt);
  }

  async encryptVault(): Promise<void> {
    if (this.settings.showWarnings) {
      // Show warning dialog first
      const confirmModal = new ConfirmationModal(
        this.app,
        '⚠️ Encrypt Vault',
        'This will encrypt ALL files in your vault with random filenames. Make sure you have a backup!',
        () => this.performEncryption()
      );
      confirmModal.open();
    } else {
      this.performEncryption();
    }
  }

  private performEncryption(): void {
    new PasswordModal(this.app, '🔒 Encrypt Vault', async (password: string) => {
      const notice = new Notice('Encrypting vault...', 0);
      
      try {
        await this.encryption.encryptVault(password, (current: number, total: number, status: string) => {
          notice.setMessage(`${status} (${current}/${total})`);
        });
        
        this.isEncrypted = true;
        notice.hide();
        new Notice('Vault encrypted successfully!');
        
      } catch (error) {
        notice.hide();
        const errorMessage = error instanceof Error ? error.message : 'Unknown error';
        new Notice(`Encryption failed: ${errorMessage}`);
        console.error('Encryption error:', error);
      }
    }).open();
  }

  async decryptVault(): Promise<void> {
    new PasswordModal(this.app, 'Decrypt Vault', async (password: string) => {
      const notice = new Notice('Decrypting vault...', 0);
      
      try {
        await this.encryption.decryptVault(password, (current: number, total: number, status: string) => {
          notice.setMessage(`${status} (${current}/${total})`);
        });
        
        this.isEncrypted = false;
        notice.hide();
        new Notice('Vault decrypted successfully!');
        
      } catch (error) {
        notice.hide();
        const errorMessage = error instanceof Error ? error.message : 'Unknown error';
        new Notice(`Decryption failed: ${errorMessage}`);
        console.error('Decryption error:', error);
      }
    }).open();
  }
}

class ConfirmationModal extends Modal {
  private title: string;
  private message: string;
  private onConfirm: () => void;

  constructor(app: App, title: string, message: string, onConfirm: () => void) {
    super(app);
    this.title = title;
    this.message = message;
    this.onConfirm = onConfirm;
  }

  onOpen(): void {
    const { contentEl } = this;
    contentEl.createEl('h2', { text: this.title });
    contentEl.createEl('p', { text: this.message });

    const buttonContainer = contentEl.createDiv({cls: 'button-container-top-margin'});

    const confirmBtn = buttonContainer.createEl('button', { text: 'Encrypt Vault' });
    const cancelBtn = buttonContainer.createEl('button', { text: 'Cancel' });

    confirmBtn.onclick = () => {
      this.close();
      this.onConfirm();
    };

    cancelBtn.onclick = () => this.close();
  }

  onClose(): void {
    const { contentEl } = this;
    contentEl.empty();
  }
}

class VaultEncryptionSettingTab extends PluginSettingTab {
  plugin: VaultEncryptionPlugin;

  constructor(app: App, plugin: VaultEncryptionPlugin) {
    super(app, plugin);
    this.plugin = plugin;
  }

  display(): void {
    const { containerEl } = this;
    containerEl.empty();

	new Setting(containerEl).setName('Vault Encryption Settings').setHeading();

    new Setting(containerEl)
      .setName('PBKDF2 Iterations')
      .setDesc('Higher values are more secure but slower (default: 100,000)')
      .addSlider(slider => slider
        .setLimits(50000, 500000, 10000)
        .setValue(this.plugin.settings.encryptionIterations)
        .setDynamicTooltip()
        .onChange(async (value) => {
          this.plugin.settings.encryptionIterations = value;
          await this.plugin.saveSettings();
        }));

    new Setting(containerEl)
      .setName('Show Warning Dialogs')
      .setDesc('Show confirmation dialogs before encryption operations')
      .addToggle(toggle => toggle
        .setValue(this.plugin.settings.showWarnings)
        .onChange(async (value) => {
          this.plugin.settings.showWarnings = value;
          await this.plugin.saveSettings();
        }));

    new Setting(containerEl)
      .setName('Auto Backup Reminder')
      .setDesc('Remind to backup before encryption (recommended)')
      .addToggle(toggle => toggle
        .setValue(this.plugin.settings.autoBackup)
        .onChange(async (value) => {
          this.plugin.settings.autoBackup = value;
          await this.plugin.saveSettings();
        }));
  }
}

import { App, Modal, Notice, Plugin, PluginSettingTab, Setting, TFile, Menu } from 'obsidian';

const DEFAULT_SETTINGS: VaultEncryptionSettings = {
  encryptionIterations: 100000,
  showWarnings: true,
  autoBackup: true
};

interface FilenameMapping {
  original: string;
  encrypted: string;
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

type StatusCallback = (current: number, total: number, status: string) => void;

class SecureVaultEncryption {
  private app: App;
  private readonly algorithm = 'AES-GCM';
  private readonly ivLength = 12;  // 96 bits (recommended for GCM)
  private readonly saltLength = 32; // 256 bits
  private readonly iterations = 100000; // PBKDF2 iterations

  constructor(app: App) {
    this.app = app;
  }

  private async deriveKey(password: string, salt: Uint8Array): Promise<CryptoKey> {
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

  /**
   * Decrypts base64 content
   */
  async decryptText(encryptedBase64: string, password: string): Promise<string> {
    try {
      // Convert from base64
      const encryptedData = this.base64ToArrayBuffer(encryptedBase64);
      const dataView = new Uint8Array(encryptedData);
      
      // Extract components
      const salt = dataView.slice(0, this.saltLength);
      const iv = dataView.slice(this.saltLength, this.saltLength + this.ivLength);
      const encrypted = dataView.slice(this.saltLength + this.ivLength);
      
      // Derive key
      const key = await this.deriveKey(password, salt);
      
      // Decrypt
      const decrypted = await crypto.subtle.decrypt(
        { name: this.algorithm, iv: iv },
        key,
        encrypted
      );
      
      // Convert back to text
      const decoder = new TextDecoder();
      return decoder.decode(decrypted);
      
    } catch (error) {
      console.error('Decryption failed:', error);
      throw new Error('Decryption failed: Invalid password or corrupted data');
    }
  }

  /**
   * Generates a secure random filename
   */
  private generateEncryptedFilename(): string {
    const randomBytes = crypto.getRandomValues(new Uint8Array(16));
    const base64 = btoa(String.fromCharCode(...randomBytes))
      .replace(/[^a-zA-Z0-9]/g, '') // Remove special characters
      .substring(0, 12); // Keep reasonable length
    return `enc_${base64}.md`;
  }

  /**
   * Creates a filename mapping entry
   */
  private createFilenameMapping(originalPath: string, encryptedFilename: string): FilenameMapping {
    return {
      original: originalPath,
      encrypted: encryptedFilename,
      timestamp: new Date().toISOString()
    };
  }

  /**
   * Encrypts the filename mapping
   */
  private async encryptFilenameMapping(mappings: FilenameMapping[], password: string): Promise<string> {
    const mappingJson = JSON.stringify(mappings, null, 2);
    return await this.encryptText(mappingJson, password);
  }

  /**
   * Decrypts the filename mapping
   */
  private async decryptFilenameMapping(encryptedMapping: string, password: string): Promise<FilenameMapping[]> {
    const decryptedJson = await this.decryptText(encryptedMapping, password);
    return JSON.parse(decryptedJson) as FilenameMapping[];
  }

  /**
   * Encrypts an entire vault
   */
  async encryptVault(password: string, statusCallback?: StatusCallback): Promise<EncryptionResult> {
    const files = this.app.vault.getFiles();
    const encryptedFiles: string[] = [];
    const filenameMapping: FilenameMapping[] = [];
    let processed = 0;

    // Skip already encrypted files and mapping file
    const filesToEncrypt = files.filter(f => 
      !f.name.startsWith('enc_') && 
      f.name !== 'vault_mapping.encrypted'
    );

    for (const file of filesToEncrypt) {
      try {
        statusCallback?.(processed, filesToEncrypt.length, `Encrypting: ${file.name}`);

        // Generate encrypted filename
        const encryptedFilename = this.generateEncryptedFilename();
        
        // Read file content
        const content = await this.app.vault.read(file);
        
        // Encrypt content
        const encryptedContent = await this.encryptText(content, password);
        
        // Create filename mapping entry
        const mappingEntry = this.createFilenameMapping(file.path, encryptedFilename);
        filenameMapping.push(mappingEntry);
        
        // Format as encrypted file (without revealing original name)
        const formattedContent = this.formatEncryptedFile(encryptedContent, encryptedFilename);
        
        // Create encrypted file with random name
        await this.app.vault.create(encryptedFilename, formattedContent);
        
        // Delete original file
        await this.app.vault.delete(file);
        
        encryptedFiles.push(encryptedFilename);
        processed++;
        
      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : 'Unknown error';
        console.error(`Failed to encrypt ${file.name}:`, error);
        throw new Error(`Failed to encrypt ${file.name}: ${errorMessage}`);
      }
    }

    // Create and encrypt the filename mapping
    try {
      statusCallback?.(processed, filesToEncrypt.length, 'Creating filename mapping...');
      
      const encryptedMapping = await this.encryptFilenameMapping(filenameMapping, password);
      const mappingContent = this.formatMappingFile(encryptedMapping);
      
      await this.app.vault.create('vault_mapping.encrypted', mappingContent);
      
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';
      console.error('Failed to create filename mapping:', error);
      throw new Error(`Failed to create filename mapping: ${errorMessage}`);
    }

    statusCallback?.(processed, filesToEncrypt.length, 'Encryption complete');
    return { encryptedFiles, mappingCreated: true };
  }

  /**
   * Decrypts entire vault
   */
  async decryptVault(password: string, statusCallback?: StatusCallback): Promise<string[]> {
    // First, decrypt the filename mapping
    let filenameMapping: FilenameMapping[] = [];
    
    try {
      statusCallback?.(0, 1, 'Reading filename mapping...');
      
      const mappingFile = this.app.vault.getAbstractFileByPath('vault_mapping.encrypted');
	  console.log(mappingFile)
      if (!mappingFile || !(mappingFile instanceof TFile)) {
        throw new Error('Filename mapping not found. Cannot decrypt vault.');
      }
      
      const mappingContent = await this.app.vault.read(mappingFile);
      const { content: encryptedMapping } = this.parseMappingFile(mappingContent);
      
      if (!encryptedMapping) {
        throw new Error('Invalid mapping file format');
      }
      
      filenameMapping = await this.decryptFilenameMapping(encryptedMapping, password);
      
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';
      console.error('Failed to decrypt filename mapping:', error);
      throw new Error(`Failed to decrypt filename mapping: ${errorMessage}`);
    }

    // Get all encrypted files
    const encryptedFiles = this.app.vault.getFiles().filter(f => 
      f.name.startsWith('enc_') && f.name.endsWith('.md')
    );
    
    const decryptedFiles: string[] = [];
    let processed = 0;

    for (const file of encryptedFiles) {
      try {
        statusCallback?.(processed, encryptedFiles.length, `Decrypting: ${file.name}`);

        // Find original filename from mapping
        const mappingEntry = filenameMapping.find(m => m.encrypted === file.name);
        if (!mappingEntry) {
          console.warn(`No mapping found for ${file.name}, skipping...`);
          continue;
        }

        // Read encrypted file
        const encryptedContent = await this.app.vault.read(file);
        
        // Parse encrypted content
        const { content: encryptedData } = this.parseEncryptedFile(encryptedContent);
        
        if (!encryptedData) {
          throw new Error('Invalid encrypted file format');
        }
        
        // Decrypt content
        const decryptedContent = await this.decryptText(encryptedData, password);
        
        // Restore original file with original name
        const originalPath = mappingEntry.original;
        
        // Ensure directory exists
        const dirPath = originalPath.substring(0, originalPath.lastIndexOf('/'));
        if (dirPath && !this.app.vault.getAbstractFileByPath(dirPath)) {
          // Create intermediate folders if needed
          const folders = dirPath.split('/');
          let currentPath = '';
          for (const folder of folders) {
            currentPath += (currentPath ? '/' : '') + folder;
            if (!this.app.vault.getAbstractFileByPath(currentPath)) {
              await this.app.vault.createFolder(currentPath);
            }
          }
        }
        
        await this.app.vault.create(originalPath, decryptedContent);
        
        // Delete encrypted file
        await this.app.vault.delete(file);
        
        decryptedFiles.push(originalPath);
        processed++;
        
      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : 'Unknown error';
        console.error(`Failed to decrypt ${file.name}:`, error);
        throw new Error(`Failed to decrypt ${file.name}: ${errorMessage}`);
      }
    }

    // Delete the mapping file
    try {
      const mappingFile = this.app.vault.getAbstractFileByPath('vault_mapping.encrypted');
      if (mappingFile) {
        await this.app.vault.delete(mappingFile);
      }
    } catch (error) {
      console.warn('Failed to delete mapping file:', error);
    }

    statusCallback?.(processed, encryptedFiles.length, 'Decryption complete');
    return decryptedFiles;
  }

  /**
   * Formats encrypted content for Obsidian (no filename revealed)
   */
  private formatEncryptedFile(encryptedBase64: string, encryptedFilename: string): string {
    const timestamp = new Date().toISOString();
    
    return `
> ⚠️ **This file is encrypted**  
> Use the Vault Encryption plugin to decrypt this content.  
> Original filename is hidden for security.

\`\`\`encrypted
${this.formatBase64WithLineBreaks(encryptedBase64)}
\`\`\`

---
*Encrypted with Obsidian Vault Encryption Plugin*`;
  }

  /**
   * Formats the filename mapping file
   */
  private formatMappingFile(encryptedMapping: string): string {
    const timestamp = new Date().toISOString();
    
    return `
> ⚠️ **This file contains encrypted filename mappings**  
> Do not delete this file - it's required to decrypt your vault.  
> Original filenames and paths are encrypted within.

\`\`\`mapping
${this.formatBase64WithLineBreaks(encryptedMapping)}
\`\`\`

---
*Generated by Obsidian Vault Encryption Plugin*`;
  }

  /**
   * Parses encrypted file back to data (updated for new format)
   */
  private parseEncryptedFile(content: string): ParsedEncryptedFile {
    const match = content.match(/```encrypted\n([\s\S]*?)\n```/);
    if (!match) {
      return { content: null };
    }

    // Clean up base64 data
    const base64Data = match[1].replace(/\s/g, '');
    
    return { content: base64Data };
  }

  /**
   * Parses filename mapping file
   */
  private parseMappingFile(content: string): ParsedMappingFile {
    const match = content.match(/```mapping\n([\s\S]*?)\n```/);
    if (!match) {
      return { content: null };
    }

    // Clean up base64 data
    const base64Data = match[1].replace(/\s/g, '');
    
    return { content: base64Data };
  }

  /**
   * Utility functions
   */
  private formatBase64WithLineBreaks(base64: string, lineLength: number = 64): string {
    const regex = new RegExp(`.{1,${lineLength}}`, 'g');
    const matches = base64.match(regex);
    return matches ? matches.join('\n') : base64;
  }

  private arrayBufferToBase64(buffer: ArrayBuffer): string {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
  }

  private base64ToArrayBuffer(base64: string): ArrayBuffer {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
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
      placeholder: 'Enter vault password...'
    });
    
    inputEl.style.width = '100%';
    inputEl.style.marginBottom = '16px';

    const buttonContainer = contentEl.createDiv();
    buttonContainer.style.display = 'flex';
    buttonContainer.style.gap = '8px';

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
}

export default class VaultEncryptionPlugin extends Plugin {
  private encryption!: SecureVaultEncryption;
  settings!: VaultEncryptionSettings;

  async onload(): Promise<void> {
    await this.loadSettings();
    
    this.encryption = new SecureVaultEncryption(this.app);

    // Add ribbon icon
    this.addRibbonIcon('lock', 'Vault Encryption', (evt: MouseEvent) => {
      this.showEncryptionMenu(evt);
    });

    // Add commands
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

    // Add settings tab
    this.addSettingTab(new VaultEncryptionSettingTab(this.app, this));

    console.log('Vault Encryption Plugin loaded');
  }

  async loadSettings(): Promise<void> {
    this.settings = Object.assign({}, DEFAULT_SETTINGS, await this.loadData());
  }

  async saveSettings(): Promise<void> {
    await this.saveData(this.settings);
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
        'Encrypt Vault',
        'This will encrypt ALL files in your vault with random filenames. Make sure you have a backup!',
        () => this.performEncryption()
      );
      confirmModal.open();
    } else {
      this.performEncryption();
    }
  }

  private performEncryption(): void {
    new PasswordModal(this.app, 'Encrypt Vault', async (password: string) => {
      const notice = new Notice('Encrypting vault...', 0);
      
      try {
        await this.encryption.encryptVault(password, (current: number, total: number, status: string) => {
          notice.setMessage(`${status} (${current}/${total})`);
        });
        
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

  onunload(): void {
    console.log('Vault Encryption Plugin unloaded');
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

    const buttonContainer = contentEl.createDiv();
    buttonContainer.style.display = 'flex';
    buttonContainer.style.gap = '8px';
    buttonContainer.style.marginTop = '16px';

    const confirmBtn = buttonContainer.createEl('button', { text: 'Encrypt Vault' });
    const cancelBtn = buttonContainer.createEl('button', { text: 'Cancel' });

    confirmBtn.style.backgroundColor = '#e74c3c';
    confirmBtn.style.color = 'white';

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

using System.Text.RegularExpressions;
using SharpPdb.Native;
using AsmResolver;
using AsmResolver.PE;
using AsmResolver.PE.File;
using AsmResolver.PE.File.Headers;
using AsmResolver.PE.Exports;
using AsmResolver.PE.Imports;
using AsmResolver.PE.Imports.Builder;
using AsmResolver.PE.Exports.Builder;

string[] functionSkipPrefixes = new string[]{
		"_",
		"?__",
		"??_",
		"??@",
		"?$TSS",
		"??_C",
		"??3",
		"??2",
		"??_R4",
		"??_E",
		"??_G"
};

List<Regex> regexList = new List<Regex>();
regexList.Add(new Regex(@"\?+[a-zA-Z0-9_-]*([a-zA-Z0-9_-]*@)*std@@.*", RegexOptions.Compiled | RegexOptions.IgnoreCase));
regexList.Add(new Regex(".*printf$", RegexOptions.Compiled | RegexOptions.IgnoreCase));
regexList.Add(new Regex(".*no_alloc.*", RegexOptions.Compiled | RegexOptions.IgnoreCase));

PdbFileReader pdbReader = new PdbFileReader("bedrock_server.pdb");
PEFile bedrockFile = PEFile.FromFile("bedrock_server.exe");
IPEImage bedrockImage = PEImage.FromFile(bedrockFile);
PESection lastSection = bedrockFile.Sections.Last();

PESection exportSection = new PESection("ExpSect", SectionFlags.MemoryRead | SectionFlags.ContentInitializedData);
ExportDirectoryBuffer exportBuffer = new ExportDirectoryBuffer();
ExportDirectory newExports = new ExportDirectory("ExpDir");
foreach(var export in bedrockImage.Exports.Entries) {
	ExportedSymbol sym = new ExportedSymbol(exportSection.Contents.ToReference());
	sym.Address = export.Address;
	sym.Name = export.Name;
	newExports.Entries.Add(sym);
}

foreach (PdbPublicSymbol sym in pdbReader.PublicSymbols) {
	if (IsFunctionExportable(sym)) {
		ExportedSymbol newSym = new ExportedSymbol(exportSection.Contents.ToReference());
		newSym.Name = sym.Name;
		newSym.Address.UpdateOffsets((ulong)sym.Offset, (uint)sym.RelativeVirtualAddress);
		newExports.Entries.Add(newSym);
		//Console.WriteLine(newSym.Name);
	}
}

exportBuffer.AddDirectory(newExports);
exportSection.Contents = exportBuffer;
bedrockFile.Sections.Add(exportSection);

ImportDirectoryBuffer importDirectory = new ImportDirectoryBuffer(false);
ImportedModule preloaderModule = new ImportedModule("LLPreLoader.dll");
ImportedSymbol dlsymSymbol = new ImportedSymbol(0, "dlsym_real");
preloaderModule.Symbols.Add(dlsymSymbol);

foreach (var import in bedrockImage.Imports) {
	importDirectory.AddModule(import);
}
importDirectory.AddModule(preloaderModule);

PESection importSection = new PESection("ImpSect", SectionFlags.MemoryRead | SectionFlags.MemoryWrite | SectionFlags.ContentInitializedData);
importSection.Contents = importDirectory;
bedrockFile.Sections.Add(importSection);
bedrockFile.AlignSections();

DataDirectory exportHeader = new DataDirectory(exportSection.Rva, exportSection.Contents.GetVirtualSize());
DataDirectory importHeader = new DataDirectory(importSection.Rva, importSection.Contents.GetVirtualSize());
bedrockFile.OptionalHeader.DataDirectories[(int)DataDirectoryIndex.ExportDirectory] = exportHeader;
bedrockFile.OptionalHeader.DataDirectories[(int)DataDirectoryIndex.ImportDirectory] = importHeader;
bedrockFile.UpdateHeaders();
bedrockFile.Write("BedrockLLTest.exe");
bedrockImage = PEImage.FromFile("BedrockLLTest.exe");
foreach(var import in bedrockImage.Imports) {
	if(import.Name == "LLPreLoader.dll") {
		import.Symbols[0].AddressTableEntry.UpdateOffsets(importSection.Offset, importSection.Rva);
    }
}

bedrockFile.Write("BedrockLLTest.exe");
Console.WriteLine("Done.");

bool IsFunctionExportable(PdbPublicSymbol symbolToTest) {
	if (symbolToTest.IsFunction) {
		return false;
	}
	if (!symbolToTest.Name.StartsWith('?')) {
		return false;
	}
	foreach (string prefix in functionSkipPrefixes) {
		if (symbolToTest.Name.StartsWith(prefix)) {
			return false;
		}
	}
	foreach (Regex reg in regexList) {

		if (reg.IsMatch(symbolToTest.Name)) {
			return false;
		}
	}
	return true;
}
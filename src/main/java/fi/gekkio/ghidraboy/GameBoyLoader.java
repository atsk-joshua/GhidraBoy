// Copyright 2019-2020 Joonas Javanainen <joonas.javanainen@gmail.com>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package fi.gekkio.ghidraboy;

import static fi.gekkio.ghidraboy.BootRomUtils.detectBootRom;
import static fi.gekkio.ghidraboy.RomUtils.detectRom;

import ghidra.app.util.Option;
import ghidra.app.util.OptionUtils;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.opinion.*;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

public class GameBoyLoader extends AbstractProgramLoader {
  private static final String OPT_HW_BLOCKS = "Create GB hardware memory blocks";
  private static final String OPT_DATA_TYPES = "Create GB data types";
  private static final String OPT_KIND = "Hardware type";

  @Override
  public String getName() {
    return "Game Boy";
  }

  @Override
  public LoaderTier getTier() {
    return LoaderTier.SPECIALIZED_TARGET_LOADER;
  }

  @Override
  public int getTierPriority() {
    return 0;
  }

  @Override
  public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
    var result = new ArrayList<LoadSpec>();
    if (detectBootRom(provider).isPresent() || detectRom(provider).isPresent()) {
      result.add(
          new LoadSpec(
              this, 0, new LanguageCompilerSpecPair("SM83:LE:16:default", "default"), true));
    }
    return result;
  }

  @Override
  public List<Option> getDefaultOptions(
      ByteProvider provider,
      LoadSpec loadSpec,
      DomainObject domainObject,
      boolean isLoadIntoProgram,
      boolean mirrorFsLayout) {
    var result =
        super.getDefaultOptions(
            provider, loadSpec, domainObject, isLoadIntoProgram, mirrorFsLayout);
    result.add(new Option("Input mode", "AUTO"));
    result.add(new Option("Mapper override", "AUTO"));
    result.add(new Option(OPT_HW_BLOCKS, true));
    result.add(new Option(OPT_DATA_TYPES, true));
    try {
      var bootRom = detectBootRom(provider);
      if (bootRom.isPresent()) {
        result.add(new GameBoyKindOption(OPT_KIND, bootRom.get()));
        return result;
      }
      var rom = detectRom(provider);
      if (rom.isPresent()) {
        result.add(new GameBoyKindOption(OPT_KIND, rom.get()));
        return result;
      }
    } catch (IOException ignored) {
    }
    result.add(new GameBoyKindOption(OPT_KIND, GameBoyKind.GB));
    return result;
  }

  @Override
  protected List<Loaded<Program>> loadProgram(ImporterSettings settings)
      throws IOException, LoadException, CancelledException {
    var program = createProgram(settings);
    boolean success = false;
    try {
      loadInto(program, settings);
      success = true;
      return List.of(new Loaded<Program>(program, settings));
    } finally {
      if (!success) program.release(settings.consumer());
    }
  }

  @Override
  protected void loadProgramInto(Program program, ImporterSettings settings)
      throws IOException, LoadException, CancelledException {
    var options = settings.options();
    try {
      CartridgeLayout.load(
          program,
          settings.provider(),
          OptionUtils.getOption("Input mode", options, "AUTO"),
          OptionUtils.getOption("Mapper override", options, "AUTO"),
          OptionUtils.getOption(OPT_KIND, options, GameBoyKind.GB),
          OptionUtils.getBooleanOptionValue(OPT_HW_BLOCKS, options, true),
          OptionUtils.getBooleanOptionValue(OPT_DATA_TYPES, options, true),
          settings.monitor(),
          settings.log());
    } catch (CancelledException e) {
      throw e;
    } catch (Exception e) {
      throw new IOException("Game Boy import failed: " + e.getMessage(), e);
    }
  }
}

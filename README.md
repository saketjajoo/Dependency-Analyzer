# Dependency-Analyzer
Dependency-Analyzer is built to compare and correlate `dependency tree` and `dependency check report`s and thus gain insights into the source of all vulnerable dependencies and the CVEs associated with them. The output is generated such that it gives information about all vulnerable dependencies and pinpoints where exactly it came from in the software/project.

## Requirements
- python3
- dependency check report in `csv` or `csv.gz` format.
- dependency tree in `.txt` format.

## Usage
``` python3 main.py <dependency_tree_file_path> <dependency_check_report_path> ```

## Dependency Tree
* For maven based projects, the [dependency tree](https://maven.apache.org/plugins/maven-dependency-plugin/tree-mojo.html) can be generated using `mvn dependency:tree [-DoutputFile=output_file.txt]`
* For npm based projects, the [dependency tree](https://docs.npmjs.com/cli/v7/commands/npm-ls) can be generated using `npm list >> output_file.txt`
  * By default, `npm list` generates output with unicode characters. Make sure that the unicode character scheme is set to **false** so that the text is parsable by python. To do so, use `npm config set unicode false`
* For sbt based projects, the [sbt-dependency-graph plugin](https://github.com/sbt/sbt-dependency-graph) can be used to generate dependency tree. Eg: `sbt "dependencyTree::toFile output_file.txt"`
  * Note: using the plugin [version >=0.10.0-RC1](https://github.com/sbt/sbt-dependency-graph/issues/167) allows the tree to be stored in a text file.

## OWASP Dependency Check
- Dependency Check tool can be used to gather security-related information about various dependencies used in a project: https://github.com/jeremylong/DependencyCheck.
- The different langauges supported by the tool for scanning are present [here](https://jeremylong.github.io/DependencyCheck/analyzers/).

## Output
The output lists all vulnerable dependencies in a project upon correlating the dependency tree with the dependency check report. For each dependency, the output shows the source of the dependency (snippet of dependency tree), the CVE(s) associated with it, the CVSSv2 and CVSSv3 scores. Also, if a dependency tree is the output of building a large project/software with various sub-projects, the `"projects"` key in the output shows all those the sub-project(s) that pulls in the particular dependency.

[Apache Spark](https://github.com/apache/spark) and [Apache Druid](https://github.com/apache/druid) projects are scanned/built and their corresponding dependency trees and dependency check reports are stored in the `examples/` folder.
  - A sample output of running Dependency-Analyzer on Druid, is stored at `examples/output.json`.

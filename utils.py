import logging, gzip, io, csv
from copy import copy
import sys

def build_stack(data):
    stack = []
    for line in data.split("\n"):
        if not line:
            continue
        level = line.count(" ")
        level = int(level//3)
        name = line

        # If the 1st character is not a lower case alphabet [dependency_name], it means that it is be a space character and needs to be stripped off)
        if not (ord(line[0].lower()) >= 97 and ord(line[0].lower()) <= 122):
            name = line.strip()
        stack = stack[:level] + [name]
        yield stack[:level], name

def create_tree(log, dependency_tree):
    tree = {}
    try:
        for stack, name in build_stack(dependency_tree):
            temp_tree = tree
            for n in stack:
                temp_tree = temp_tree.setdefault(n, {})
            temp_tree[name] = {}
    except Exception as e:
        log.error(str(e))
    return tree

def read_dependency_tree(log, file_path):
    data = []
    try:
        f = open(file_path, "r")
        data = f.read()
        f.close()
    except Exception as e:
        log.error(str(e))
    return  data

def read_dependency_check_report(log, file_path):
    result = (None, None)
    final_columns, final_values = [], []

    try:
        if file_path.endswith(".csv.gz"):
            with gzip.open(file_path, 'rb') as fh:
                reader = csv.DictReader(io.TextIOWrapper(fh))
        else:
            reader = csv.DictReader(open(file_path))
        for row in reader:
            values = []
            final_columns = list(row.keys())
            for col in final_columns:
                values.append(row[col])
            final_values.append(values)
    except Exception as e:
        log.error(str(e))

    result = (final_columns, final_values)
    return result

def get_dependency_check_data(log, dependency_check_report):
    try:
        return dependency_check_report[0], dependency_check_report[1]
    except Exception as e:
        log.error(str(e))
        return None, None

def dep_exists_in_release(dependency_tree, dependency_name, dependency_version):
    for k, v in dependency_tree.items():
        path.append(k)
        if isinstance(v, dict):
            dep_exists_in_release(v, dependency_name, dependency_version)
            tree_dep_name, tree_dep_version = "", ""
            # checking for javascript dependencies
            if "@" in k:
                if k[0] == "@": # (eg. @superset-ui/legacy-plugin-chart-pivot-table@0.10.11)
                    tree_dep_name = k.split("@")[1]
                    tree_dep_version = k.split("@")[2]
                else: # (eg. jquery@3.5.1)
                    tree_dep_name = k.split("@")[0]
                    tree_dep_version = k.split("@")[1]
            # checking for java dependencies
            elif ":" in k:
                tree_dep_name = k.split(":")[1]
                if len(k.split(":")) > 3: # (eg. org.slf4j:slf4j-api:jar:1.7.30:compile)
                    tree_dep_version = k.split(":")[3]
                else: # (eg. org.apache.thrift:libthrift:0.9.3)
                    tree_dep_version = k.split(":")[2]
            if dependency_name in tree_dep_name and dependency_version in tree_dep_version:
                result.append(copy(path))
            path.pop()

def check_occurrence_in_dependency_tree(dependency_tree, dependency_name, dependency_version):
    if dependency_name != "":
        global result, path
        result, path = [], []
        dep_exists_in_release(dependency_tree, dependency_name, dependency_version)
        return result
    else:
        return []

def generate_dependency_check_parsed_data(log, dependency_tree, dependency_check_data_columns, dependency_check_data_values):
    dependency_check_parsed_data = []
    try:
        cve_column = dependency_check_data_columns.index("CVE")
        sev2_column = dependency_check_data_columns.index("CVSSv2_Severity")
        sev3_column = dependency_check_data_columns.index("CVSSv3_BaseSeverity")
        identifiers_column =dependency_check_data_columns.index("Identifiers")

        if cve_column != None and sev2_column != None and sev3_column != None and identifiers_column != None:
            for i in range(len(dependency_check_data_values)):
                inner_d = {}
                if dependency_check_data_values[i][cve_column].startswith("CVE-"):
                    if str(dependency_check_data_values[i][identifiers_column]).lower().strip() != "nan":
                        inner_d["cve"] = dependency_check_data_values[i][cve_column]
                        if dependency_check_data_values[i][sev2_column] == dependency_check_data_values[i][sev2_column]:
                            inner_d["cvssv2_sev"] = dependency_check_data_values[i][sev2_column]
                        else:
                            inner_d["cvssv2_sev"] = "NONE"
                        if (dependency_check_data_values[i][sev3_column] == dependency_check_data_values[i][sev3_column]) and (str(dependency_check_data_values[i][sev3_column]).strip() != ""):
                            inner_d["cvssv3_sev"] = dependency_check_data_values[i][sev3_column]
                        else:
                            inner_d["cvssv3_sev"] = "NONE"
                        if "maven" in dependency_check_data_values[i][identifiers_column]:
                            inner_d["identifiers"] = dependency_check_data_values[i][identifiers_column]
                            dependency_check_parsed_data.append(inner_d)
            del dependency_check_data_columns
            del dependency_check_data_values
            for i in range(len(dependency_check_parsed_data)):
                dependency_name = dependency_check_parsed_data[i]["identifiers"].split("/")[-1].split("@")[0]
                dependency_version = dependency_check_parsed_data[i]["identifiers"].split("@")[1]
                result = check_occurrence_in_dependency_tree(dependency_tree, dependency_name, dependency_version)
                temp_list = set()
                for k in range(len(result)):
                    temp_list.add(result[k][0].split(":")[0])
                dependency_check_parsed_data[i]["projects"] = list(temp_list)
                dependency_check_parsed_data[i]["result"] = result

    except Exception as e:
        log.error(str(e))

    return dependency_check_parsed_data

def group_by_dependency(log, dependency_check_parsed_data):
    try:
        all_dependencies = set()
        for i in range(len(dependency_check_parsed_data)):
            if dependency_check_parsed_data[i].get("identifiers"):
                all_dependencies.add(dependency_check_parsed_data[i]["identifiers"])
    except Exception as e:
        log.error(str(e))

    result = []
    try:
        all_dependencies = list(all_dependencies)
        cve_identifier_seen_dict = {}

        for dependency in all_dependencies:

            cve_identifier_seen_dict[dependency] = []

            dict = {}
            dict["dependency"] = dependency
            deps_list = []
            for i in range(len(dependency_check_parsed_data)):
                if dependency_check_parsed_data[i].get("identifiers") == dependency:
                    deps_list.append(dependency_check_parsed_data[i])

            unique_projects = set()
            for i in range(len(deps_list)):
                if deps_list[i].get("projects"):
                    for j in range(len(deps_list[i]["projects"])):
                        unique_projects.add(deps_list[i]["projects"][j])

            unique_projects = list(unique_projects)
            dict["projects"] = unique_projects
            dict["data"] = []

            for i in range(len(unique_projects)):
                inner_d = {}
                inner_d[unique_projects[i]] = []
                for j in range(len(deps_list)):
                    inner_inner_d = {}
                    if unique_projects[i] in deps_list[j].get("projects"):
                        inner_inner_d["cve"] = deps_list[j].get("cve")
                        inner_inner_d["cvssv2_sev"] = deps_list[j].get("cvssv2_sev")
                        inner_inner_d["cvssv3_sev"] = deps_list[j].get("cvssv3_sev")
                        inner_inner_d["evidence"] = []
                        for k in range(len(deps_list[j].get("result"))):
                            if unique_projects[i] in deps_list[j].get("result")[k][0]:
                                inner_inner_d["evidence"].append(deps_list[j].get("result")[k])
                        inner_d[unique_projects[i]].append(inner_inner_d)
                dict["data"].append(inner_d)
            result.append(dict)

    except Exception as e:
        log.error(e)

    return result

import sys, logging, json
import utils

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s %(name)s %(levelname)s: %(message)s')
log = logging.getLogger(__name__)

def usage():
    print("USAGE:", "python3 main.py <dependency_tree_file_path> <dependency_check_report_path>")

if __name__ == "__main__":

    if len(sys.argv) != 3:
        usage()
        log.error("Incorrect Usage.")
        exit(1)

    dependency_tree_file_path = str(sys.argv[1])
    dependency_check_report_path = str(sys.argv[2])

    dependency_tree = utils.read_dependency_tree(log, dependency_tree_file_path)
    dependency_check_report = utils.read_dependency_check_report(log, dependency_check_report_path)

    if dependency_tree == [] or dependency_check_report == (None, None):
        sys.exit(1)
    else:
        dependency_tree = dependency_tree.split("\n")
        for i in range(len(dependency_tree)):
            dependency_tree[i] = dependency_tree[i].replace("\-", "  ").replace("|", " ").replace("+-", "  ").rstrip()
        dependency_tree = "\n".join(dependency_tree)
        log.info("Parsed Dependency Tree. Removed non-alphanumberic characters.")
        parsed_tree = utils.create_tree(log, dependency_tree)
        if parsed_tree == {}:
            sys.exit(1)
        log.info('Converted Dependency Tree into a dictionary.')
        dependency_check_data_columns, dependency_check_data_values = utils.get_dependency_check_data(log, dependency_check_report)

        if (dependency_check_data_columns, dependency_check_data_values) == (None, None):
            sys.exit(1)
        else:
            log.info('Fetched Dependency Check Data.')
            log.info('Correlating dependency_tree and dependency_check_data.')
            dependency_check_parsed_data = utils.generate_dependency_check_parsed_data(log, parsed_tree, dependency_check_data_columns, dependency_check_data_values)
            if dependency_check_parsed_data == []:
                sys.exit(1)
            else:
                log.info('Parsed Dependency Check Data. Now grouping by dependencies.')
                dependency_check_parsed_data = utils.group_by_dependency(log, dependency_check_parsed_data)
                if dependency_check_parsed_data == []:
                    sys.exit(1)
                f = open("output.json", "w")
                f.write(json.dumps(dependency_check_parsed_data, indent=4))
                f.close()

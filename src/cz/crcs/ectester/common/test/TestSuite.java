package cz.crcs.ectester.common.test;

import cz.crcs.ectester.data.EC_Store;

import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

/**
 * @author Jan Jancar johny@neuromancer.sk
 */
public abstract class TestSuite {
    protected String name;
    protected String description;
    protected List<Test> tests = new LinkedList<>();
    protected EC_Store dataStore;

    public TestSuite(EC_Store dataStore, String name, String description) {
        this.dataStore = dataStore;
        this.name = name;
        this.description = description;
    }

    public List<Test> getTests() {
        return Collections.unmodifiableList(tests);
    }

    public String getName() {
        return name;
    }

    public String getDescription() {
        return description;
    }

}

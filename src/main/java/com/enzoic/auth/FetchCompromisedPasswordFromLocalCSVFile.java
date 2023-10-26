package com.enzoic.auth;

import org.forgerock.openam.auth.node.api.NodeProcessException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;

/**
 * @author Sacumen(www.sacumen.com)
 * Reads local csv file and add each value in List.
 * It also stores csv file in cache and get values from the cache.
 */
public class FetchCompromisedPasswordFromLocalCSVFile {

    private final static Logger logger = LoggerFactory.getLogger(FetchCompromisedPasswordFromLocalCSVFile.class);
    private static String fileName;
    private static FetchCompromisedPasswordFromLocalCSVFile single_instance = null;
    private LoadingCache<String, List<String>> cache;

    private FetchCompromisedPasswordFromLocalCSVFile(int cacheExpirationTime) {
        cache = CacheBuilder.newBuilder().maximumSize(100).expireAfterWrite(cacheExpirationTime, TimeUnit.SECONDS)
                .build(new CacheLoader<String, List<String>>() {

                    @Override
                    public List<String> load(String key) throws Exception {
                        logger.info("loading cache..");
                        return addCache();
                    }

                });
    }

    public static FetchCompromisedPasswordFromLocalCSVFile getInstance(int cacheExpirationTime, String fileLocation)
            throws NodeProcessException {
        if (single_instance == null) {
            logger.debug("single_instance is null");
            if (!new File(fileLocation).exists()) {
                throw new NodeProcessException("Given file name " + fileLocation +
                        " is a invalid file location, Please enter valid file path.");
            }
            fileName = fileLocation;
            single_instance = new FetchCompromisedPasswordFromLocalCSVFile(cacheExpirationTime);
        }

        return single_instance;
    }

    /**
     * @return List of values present in csv file from cache
     * @throws NodeProcessException It adds cache in memory.
     */
    private List<String> addCache() throws NodeProcessException {
        logger.info("Adding cache..");
        return getCompromisedPassword();

    }

    /**
     * @throws NodeProcessException* Get List of values present in csv file from cache.
     */
    public List<String> getEntry(String key) throws NodeProcessException {
        try {
            logger.info("Getting values from cache...");
            logger.debug("Cache size is " + cache.size());
            return cache.get(key);
        } catch (ExecutionException e) {
            logger.error("Not able to get value form cache..");
            throw new NodeProcessException(e.getLocalizedMessage());
        }
    }

    /**
     * It reads values from csv file and store in a list.
     * @return List of values present in csv file.
     * @throws NodeProcessException
     */
    private List<String> getCompromisedPassword() throws NodeProcessException {
        logger.info("Getting compromised password from local file, where file location is " + fileName);
        String line;
        String cvsSplitBy = ",";
        List<String> records = new ArrayList<>();

        try (BufferedReader br = new BufferedReader(new FileReader(fileName))) {
            while ((line = br.readLine()) != null) {

                // used comma as separator
                String[] values = line.split(cvsSplitBy);
                Collections.addAll(records, values);
            }
        } catch (IOException e) {
            cache.invalidateAll();
            logger.debug("Cache size after invalidating cache is " + cache.size());
            throw new NodeProcessException(e.getLocalizedMessage());
        }
        records.forEach(logger::debug);

        return records;
    }
}

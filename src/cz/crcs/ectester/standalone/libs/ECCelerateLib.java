package cz.crcs.ectester.standalone.libs;

import iaik.security.provider.IAIK;
import iaik.security.ec.provider.ECCelerate;
import iaik.security.ec.common.ECStandardizedParameterFactory;

import java.security.Security;
import java.util.Enumeration;
import java.util.Set;
import java.util.TreeSet;

/**
 * @author Jan Jancar johny@neuromancer.sk
 */
public class ECCelerateLib extends ProviderECLibrary {

    public ECCelerateLib() {
        super(ECCelerate.getInstance());
        Security.addProvider(new IAIK());
        ECCelerate.enableSideChannelProtection(true);
    }

    @Override
    public Set<String> getCurves() {
        Set<String> result = new TreeSet<>();
        Enumeration names = ECStandardizedParameterFactory.getNames();
        while (names.hasMoreElements()) {
            result.add((String) names.nextElement());
        }
        return result;
    }
}

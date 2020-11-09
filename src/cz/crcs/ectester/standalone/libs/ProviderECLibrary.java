package cz.crcs.ectester.standalone.libs;

import cz.crcs.ectester.standalone.consts.Ident;
import cz.crcs.ectester.standalone.consts.KeyAgreementIdent;
import cz.crcs.ectester.standalone.consts.KeyPairGeneratorIdent;
import cz.crcs.ectester.standalone.consts.SignatureIdent;

import java.security.Provider;
import java.security.Security;
import java.util.HashSet;
import java.util.Set;
import java.util.function.Function;

/**
 * @author Jan Jancar johny@neuromancer.sk
 */
public abstract class ProviderECLibrary implements ECLibrary {
    Provider provider;
    private boolean initialized = false;

    public ProviderECLibrary() {

    }

    public ProviderECLibrary(Provider provider) {
        this.provider = provider;
    }

    @Override
    public boolean initialize() {
        try {
            int result = Security.addProvider(provider);
            if (result == -1) {
                provider = Security.getProvider(provider.getName());
            }
            initialized = true;
        } catch (NullPointerException | SecurityException ignored) {
            initialized = false;
        }
        return initialized;
    }

    @Override
    public boolean isInitialized() {
        return initialized;
    }

    private <T extends Ident> Set<T> getIdents(String type, Function<String, T> getter) {
        Set<T> results = new HashSet<>();
        if (!initialized) {
            return results;
        }

        for (Provider.Service service : provider.getServices()) {
            if (service.getType().equals(type)) {
                T id = getter.apply(service.getAlgorithm());
                if (id != null) {
                    results.add(id);
                }
            }
        }
        return results;
    }

    public Set<String> getNativeTimingSupport() {
        return new HashSet<>();
    }

    public boolean setNativeTimingType(String type) {
    	return false;
    }

    public long getNativeTimingResolution() {
        return 0;
    }

	public String getNativeTimingUnit() {
		return null;
	}

    public long getLastNativeTiming() {
        return 0;
    }

    @Override
    public Set<KeyAgreementIdent> getKAs() {
        return getIdents("KeyAgreement", KeyAgreementIdent::get);
    }

    @Override
    public Set<SignatureIdent> getSigs() {
        return getIdents("Signature", SignatureIdent::get);
    }

    @Override
    public Set<KeyPairGeneratorIdent> getKPGs() {
        return getIdents("KeyPairGenerator", KeyPairGeneratorIdent::get);
    }

    @Override
    public String name() {
        return provider.getName();
    }

    public Provider getProvider() {
        return provider;
    }

    @Override
    public String toString() {
        return name();
    }
}

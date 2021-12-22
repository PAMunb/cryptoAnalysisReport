package net.eneiluj.moneybuster.android.fragment.about;

import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;

import androidx.fragment.app.Fragment;

import net.eneiluj.moneybuster.R;
import net.eneiluj.moneybuster.util.SupportUtil;

public class AboutFragmentContributingTab extends Fragment {

    TextView aboutSource;
    TextView aboutIssues;
    TextView aboutTranslate;

    @Override
    public View onCreateView(LayoutInflater inflater, ViewGroup container, Bundle savedInstanceState) {
        View v = inflater.inflate(R.layout.fragment_about_contribution_tab, container, false);
        aboutSource = v.findViewById(R.id.about_source);
        aboutIssues = v.findViewById(R.id.about_issues);
        aboutTranslate = v.findViewById(R.id.about_translate);

        SupportUtil.setHtml(aboutSource, R.string.about_source, getString(R.string.url_source));
        SupportUtil.setHtml(aboutIssues, R.string.about_issues, getString(R.string.url_issues));
        SupportUtil.setHtml(aboutTranslate, R.string.about_translate, getString(R.string.url_translations));
        return v;
    }
}